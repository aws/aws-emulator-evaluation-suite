"""bootstrap-action-completes-before-the-first-step-runs."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "bootstrap-action-completes-before-the-first-step-runs"
GROUP = "data-plane"
SERVICES = ["emr"]

# ===== helpers =====

INSTANCE_TYPE = "m5.xlarge"
RELEASE_LABEL = "emr-6.15.0"

_SCENARIO = "emr-bootstrap-before-step"
_TAGS = [
    {"Key": "sim2real", "Value": _SCENARIO},
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

_EMR_SERVICE_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "elasticmapreduce.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
_EC2_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"

_CLUSTER_GONE_CODES = (
    "InvalidRequestException", "ClusterNotFound", "ResourceNotFoundException",
    "EntityNotFoundException",
)
TERMINAL_STEP_STATES = {"COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"}
TERMINAL_CLUSTER_STATES = {"TERMINATED", "TERMINATED_WITH_ERRORS"}

_CONTROL_MARKER = "MISSING"


def _swallow(fn):
    """Run a teardown call fn(), tolerating only a cluster or bucket that is gone or shut down."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        msg = err.get("Message", "")
        if not (err["Code"] == "NoSuchBucket" or (err["Code"] == "ValidationException" and (
                "Specified job flow ID not valid" in msg or "may not be modified" in msg))):
            raise


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate(result); RAISE on timeout (never return the last value)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_with_retry(fn, attempts=8, delay=15, ctx=None):
    """Run an IAM delete, retrying DeleteConflict while EMR still holds the instance profile."""
    for i in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001 — teardown; re-raised on the last attempt
            if "DeleteConflict" not in str(exc) or i == attempts - 1 or _cleanup_spent(ctx):
                raise
            time.sleep(delay)


def _ensure_emr_roles(ctx):
    """Create the EMR service role and the EC2 instance profile; returns (service, ec2) names.

    Created in-check: EMR_DefaultRole / EMR_EC2_DefaultRole do NOT exist in a fresh account, so
    naming them would surface as an untagged ClientError instead of as EMR behaviour.
    """
    iam = ctx.client("iam")
    svc_role = ctx.unique_name("sim2real-behav-emrbo-svc-")
    ec2_role = ctx.unique_name("sim2real-behav-emrbo-ec2-")

    iam.create_role(RoleName=svc_role, AssumeRolePolicyDocument=_EMR_SERVICE_TRUST, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=svc_role), ctx=ctx))
    iam.attach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY))

    iam.create_role(RoleName=ec2_role, AssumeRolePolicyDocument=_EC2_TRUST, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=ec2_role), ctx=ctx))
    iam.attach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY))

    iam.create_instance_profile(InstanceProfileName=ec2_role, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(
        lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role), ctx=ctx))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=ec2_role, RoleName=ec2_role))

    # IAM is eventually consistent; _run_cluster retries RunJobFlow through the
    # role/profile-propagation errors with a deadline, on every target.
    return svc_role, ec2_role


def _pick_subnet(ctx):
    """This check's private subnet (see _private_network)."""
    return _private_network(ctx, INSTANCE_TYPE)[1]


def _make_bucket(ctx, s3):
    """Create the scratch/log bucket, registered BEFORE the cluster so LIFO empties it AFTER."""
    bucket = ctx.unique_name("sim2real-behav-emrbo-")

    def _cleanup() -> None:
        def _purge_and_delete() -> None:
            for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
                victims = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                           for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
                if victims:
                    failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": victims}).get("Errors")
                    if failed:
                        raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            s3.delete_bucket(Bucket=bucket)

        _swallow(_purge_and_delete)

    ctx.on_cleanup(_cleanup)
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    return bucket


def _cluster_is_gone(exc):
    """True only for the error that means the cluster no longer exists."""
    code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
    return code in _CLUSTER_GONE_CODES or "is not valid" in str(exc)


def _terminate_and_await_teardown(emr, cluster_id, ctx=None):
    """Terminate and WAIT: EMR needs the service role for the whole wind-down, and cleanups run
    LIFO with the IAM deletions registered first, so a bare terminate strands EC2 instances."""
    _swallow(lambda: emr.set_termination_protection(
        JobFlowIds=[cluster_id], TerminationProtected=False))
    _swallow(lambda: emr.terminate_job_flows(JobFlowIds=[cluster_id]))
    deadline = _teardown_deadline(ctx, _CLEANUP_BUDGET_S)
    while time.monotonic() < deadline:
        try:
            state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        except Exception as exc:  # noqa: BLE001 — teardown classification only
            if _cluster_is_gone(exc):
                return
            time.sleep(2)
            continue
        if state in TERMINAL_CLUSTER_STATES:
            return
        time.sleep(2)
    raise RuntimeError(f"EMR cluster {cluster_id} did not terminate within the teardown wait")


def _run_cluster(emr, ctx, service_role, job_flow_role, **params):
    """RunJobFlow, retrying only transient IAM-propagation / throttle errors, registering teardown
    immediately after the id exists."""
    left = ctx.time_left()
    deadline = time.monotonic() + (320 if left is None else min(320, left))
    while True:
        try:
            resp = _run_job_flow_propagated(ctx, emr, ServiceRole=service_role, JobFlowRole=job_flow_role, **params)
            break
        except Exception as exc:  # noqa: BLE001 — classified below, re-raised if fatal
            low = str(exc).lower()
            transient = ("throttl" in low or "rate exceeded" in low
                         or "invalid instanceprofile" in low or "invalid ec2" in low)
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    cluster_id = resp["JobFlowId"]
    ctx.on_cleanup(lambda: _terminate_and_await_teardown(emr, cluster_id, ctx=ctx))
    return cluster_id


# ===== end helpers =====


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A bootstrap action runs BEFORE the cluster's first step: the step's S3 output carries the
    token the bootstrap action left on the node's local disk, while the same step reading a path
    the bootstrap action never created reports MISSING (the control)."""
    emr = ctx.client("emr")
    s3 = ctx.client("s3")

    bucket = _make_bucket(ctx, s3)
    service_role, job_flow_role = _ensure_emr_roles(ctx)
    subnet = _pick_subnet(ctx)

    # The token exists only in this process until the bootstrap action writes it onto the node, so
    # nothing the step could echo back other than by reading that file.
    token = ctx.unique_name("bootstrap-token-")
    local_path = f"/tmp/sim2real-bootstrap-{token}"
    # A sibling path the bootstrap action deliberately does NOT create: the step's control read.
    absent_path = f"/tmp/sim2real-never-written-{token}"

    script_key = "bootstrap/leave_token.sh"
    script = f"#!/bin/bash\nset -eu\nprintf '%s' '{token}' > {local_path}\n"
    s3.put_object(Bucket=bucket, Key=script_key, Body=script.encode("utf-8"))
    script_uri = f"s3://{bucket}/{script_key}"

    observed_key = f"steps/observed-{token}"
    control_key = f"steps/control-{token}"
    # `|| printf MISSING` and not `set -e` around it: the control read is EXPECTED to fail, and its
    # failure has to become an observable value rather than kill the step.
    step_script = (
        f"set -u; "
        f"cat {local_path} > /tmp/observed; "
        f"(cat {absent_path} > /tmp/control 2>/dev/null) "
        f"|| printf '{_CONTROL_MARKER}' > /tmp/control; "
        f"aws s3 cp /tmp/observed s3://{bucket}/{observed_key} --region {ctx.region}; "
        f"aws s3 cp /tmp/control s3://{bucket}/{control_key} --region {ctx.region}"
    )

    cluster_id = _run_cluster(
        emr, ctx, service_role, job_flow_role,
        Name=ctx.unique_name("sim2real-behav-emrbo-"),
        ReleaseLabel=RELEASE_LABEL,
        LogUri=f"s3://{bucket}/logs/",
        Applications=[{"Name": "Hadoop"}],
        Instances={
            "InstanceGroups": [{
                "Name": "sim2real-primary", "InstanceRole": "MASTER",
                "InstanceType": INSTANCE_TYPE, "InstanceCount": 1, "Market": "ON_DEMAND",
            }],
            # True so the only thing that can end this cluster is the teardown: an
            # ALL_STEPS_COMPLETED auto-shutdown would race the S3 reads below.
            "KeepJobFlowAliveWhenNoSteps": True,
            "TerminationProtected": False,
            "Ec2SubnetId": subnet,
        },
        BootstrapActions=[{
            "Name": "sim2real-leave-token",
            "ScriptBootstrapAction": {"Path": script_uri},
        }],
        Steps=[{
            "Name": "sim2real-behav-emrbo-read-token",
            "ActionOnFailure": "CONTINUE",
            "HadoopJarStep": {"Jar": "command-runner.jar", "Args": ["bash", "-c", step_script]},
        }],
        VisibleToAllUsers=True,
        Tags=_TAGS,
    )

    # The bootstrap action must be the one submitted — a target that silently dropped it would
    # otherwise reach the S3 assertions with a plausible story.
    actions = [a for page in emr.get_paginator("list_bootstrap_actions").paginate(
        ClusterId=cluster_id) for a in page["BootstrapActions"]]
    assert len(actions) == 1, (
        f"ListBootstrapActions must report exactly the one submitted action, got {actions!r}"
    )
    assert actions[0]["ScriptPath"] == script_uri, (
        f"the bootstrap action must name the submitted script; expected {script_uri!r}, got "
        f"{actions[0].get('ScriptPath')!r}"
    )

    step_id = emr.list_steps(ClusterId=cluster_id)["Steps"][0]["Id"]
    step = _poll(
        lambda: emr.describe_step(ClusterId=cluster_id, StepId=step_id)["Step"],
        lambda s: s["Status"]["State"] in TERMINAL_STEP_STATES,
        timeout_s=1500,
        interval_s=20,
        description=f"the token-reading step on {cluster_id} reaches a terminal state",
    )
    assert step["Status"]["State"] == "COMPLETED", (
        f"the step must COMPLETE — a FAILED step here means `cat {local_path}` found nothing, i.e. "
        f"the bootstrap action had not run when the step was dispatched. Got "
        f"{step['Status']['State']!r} (reason {step['Status'].get('StateChangeReason')!r})"
    )

    # --- THE assertion: an independent read at S3, of bytes that could only have come from the
    # file the bootstrap action wrote.
    observed = s3.get_object(Bucket=bucket, Key=observed_key)["Body"].read().decode("utf-8")
    assert observed == token, (
        f"the step must have read the token the bootstrap action left on the node's local disk: "
        f"expected {token!r} at s3://{bucket}/{observed_key}, got {observed!r}"
    )

    # --- the in-file control: the same step reading a path the bootstrap action never created.
    control = s3.get_object(Bucket=bucket, Key=control_key)["Body"].read().decode("utf-8")
    assert control == _CONTROL_MARKER, (
        f"the control read must report the never-written path as {_CONTROL_MARKER!r} — if it also "
        f"returned the token, the step's filesystem read is not real and the positive leg above "
        f"proves nothing. Got {control!r} at s3://{bucket}/{control_key}"
    )

    # --- and the timeline must agree, as a second independent observable on the same ordering:
    # the cluster was ready to run steps only after bootstrap, and the step started after that.
    cluster_timeline = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["Timeline"]
    ready = cluster_timeline.get("ReadyDateTime")
    assert ready is not None, (
        f"a cluster that has run a step must carry Timeline.ReadyDateTime, got {cluster_timeline!r}"
    )
    started = step["Status"]["Timeline"].get("StartDateTime")
    assert started is not None, (
        f"an executed step must carry Timeline.StartDateTime, got {step['Status']['Timeline']!r}"
    )
    assert started >= ready, (
        f"a step cannot start ({started}) before the cluster was ready to run steps ({ready}) — "
        f"bootstrap actions complete inside that window"
    )
    created = step["Status"]["Timeline"].get("CreationDateTime")
    assert created is not None, (
        f"a step must record when it was submitted, got {step['Status']['Timeline']!r}"
    )
    assert created <= started, (
        f"a step cannot start ({started}) before it was submitted ({created})"
    )


def _run_job_flow_propagated(ctx, emr, **params):
    """RunJobFlow, retrying every 2 s while IAM has not yet propagated a new instance profile to EMR
    ("Failed to authorize instance profile"), to min(180 s, the check's time left); raises the rest."""
    from botocore.exceptions import ClientError

    left = None if ctx is None else ctx.time_left()
    deadline = time.monotonic() + (180.0 if left is None else min(180.0, left))
    while True:
        try:
            return emr.run_job_flow(**params)
        except ClientError as exc:
            err = exc.response["Error"]
            propagating = (err["Code"] == "AccessDeniedException"
                           and "failed to authorize instance profile" in err.get("Message", "").lower())
            if not propagating or time.monotonic() >= deadline:
                raise
        time.sleep(2)


# ===== private network =====
#: The check's own VPC: its clusters sit in a subnet with no internet route, and a gateway
#: endpoint to S3 (all EMR needs there) is the only way out.
_PRIVATE_VPC_CIDR = "10.0.0.0/16"
_PRIVATE_SUBNET_CIDR = "10.0.0.0/24"
#: The suite's cleanup budget: one deadline per run, started by the first teardown that asks for
#: it; every teardown wait of the run is cut to it.
_CLEANUP_BUDGET_S = 900.0
_cleanup_deadlines: dict[int, tuple[object, float]] = {}
_CLUSTERS: dict[int, tuple[object, set[str]]] = {}
_NETWORK_RETRY = frozenset({
    "DependencyViolation", "InvalidGroup.NotFound", "InvalidPermission.NotFound",
    "InvalidSubnetID.NotFound", "InvalidNetworkInterfaceID.NotFound",
})
_NETWORKS: dict[int, tuple[object, tuple[str, str]]] = {}


def _private_network(ctx, instance_type: str = "m5.xlarge") -> tuple[str, str]:
    """(vpc_id, subnet_id) of this check's private network, created on first use in a zone that
    offers instance_type; its teardown is registered before any cluster is placed in it."""
    hit = _NETWORKS.get(id(ctx))
    if hit is not None and hit[0] is ctx:
        return hit[1]
    ec2 = ctx.client("ec2")
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"])
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]},
                 {"Name": "location", "Values": zones}])["InstanceTypeOfferings"]}
    usable = [z for z in zones if z in offered]
    assert usable, f"no available zone offers {instance_type}: zones {zones!r}"
    tags = [{"Key": "sim2real:managed", "Value": "true"}]
    vpc_id = ec2.create_vpc(CidrBlock=_PRIVATE_VPC_CIDR, TagSpecifications=[
        {"ResourceType": "vpc", "Tags": tags}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _drop_private_network(ctx, vpc_id))
    ctx.client("emr").meta.events.register(
        "after-call.emr.RunJobFlow", lambda parsed, **_: _track_cluster(ctx, parsed.get("JobFlowId")))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 30})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=_PRIVATE_SUBNET_CIDR, AvailabilityZone=usable[0],
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tags}])["Subnet"]["SubnetId"]
    table = ec2.describe_route_tables(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "association.main", "Values": ["true"]}])["RouteTables"][0]["RouteTableId"]
    ec2.create_vpc_endpoint(
        VpcId=vpc_id, VpcEndpointType="Gateway", RouteTableIds=[table],
        ServiceName=f"com.amazonaws.{ec2.meta.region_name}.s3",
        TagSpecifications=[{"ResourceType": "vpc-endpoint", "Tags": tags}])
    _NETWORKS[id(ctx)] = (ctx, (vpc_id, subnet_id))
    return vpc_id, subnet_id


def _cleanup_deadline(ctx) -> float:
    """The run's one teardown deadline, started by the first teardown that asks for it."""
    hit = _cleanup_deadlines.get(id(ctx))
    if hit is None or hit[0] is not ctx:
        hit = _cleanup_deadlines[id(ctx)] = (ctx, time.monotonic() + _CLEANUP_BUDGET_S)
    return hit[1]


def _teardown_deadline(ctx, cap_s: float) -> float:
    """A teardown wait's deadline: cap_s from now, cut to the run's cleanup deadline given its ctx."""
    own = time.monotonic() + cap_s
    return own if ctx is None else min(own, _cleanup_deadline(ctx))


def _cleanup_spent(ctx) -> bool:
    """The run's cleanup deadline has passed; never without a ctx."""
    return ctx is not None and time.monotonic() >= _cleanup_deadline(ctx)


def _track_cluster(ctx, cluster_id) -> None:
    """Record a cluster this check created, so the network teardown waits for it to terminate."""
    if cluster_id:
        hit = _CLUSTERS.get(id(ctx))
        if hit is None or hit[0] is not ctx:
            hit = _CLUSTERS[id(ctx)] = (ctx, set())
        hit[1].add(cluster_id)


def _drop_private_network(ctx, vpc_id: str) -> None:
    """Delete the check's VPC: wait for its EMR clusters to terminate, delete its endpoints, wait for
    its interfaces to release, clear then delete every non-default group (EMR's reference each other),
    route tables, subnets, the VPC. Retries in-use refusals every 2 s to the run's cleanup deadline."""
    from botocore.exceptions import ClientError

    _NETWORKS.pop(id(ctx), None)
    tracked = _CLUSTERS.pop(id(ctx), (ctx, set()))
    created = tracked[1] if tracked[0] is ctx else set()
    ec2 = ctx.client("ec2")
    emr = ctx.client("emr")
    in_vpc = [{"Name": "vpc-id", "Values": [vpc_id]}]
    deadline = _cleanup_deadline(ctx)

    def _emr_state(cluster_id: str) -> str:
        try:
            return emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        except ClientError as exc:
            err = exc.response["Error"]
            message = err.get("Message", "").lower()
            if err["Code"] == "ClusterNotFound" or (
                    err["Code"] == "InvalidRequestException"
                    and ("not found" in message or "is not valid" in message)):
                return "TERMINATED"
            raise

    def _teardown_pass() -> str:
        """One pass: what the VPC still waits on, or "" once it is deleted."""
        clusters = sorted(created | {t["Value"] for r in ec2.describe_instances(Filters=in_vpc)["Reservations"]
                                     for i in r["Instances"] for t in i.get("Tags", [])
                                     if t["Key"] == "aws:elasticmapreduce:job-flow-id"})
        for cluster_id in clusters:
            state = _emr_state(cluster_id)
            if state not in ("TERMINATED", "TERMINATED_WITH_ERRORS"):
                return f"cluster {cluster_id} is {state}"
        endpoints = [e for e in ec2.describe_vpc_endpoints(Filters=in_vpc)["VpcEndpoints"]
                     if e["State"].lower() != "deleted"]
        live = [e["VpcEndpointId"] for e in endpoints if e["State"].lower() != "deleting"]
        if live:
            failed = [u for u in ec2.delete_vpc_endpoints(VpcEndpointIds=live).get("Unsuccessful", [])
                      if u["Error"]["Code"] != "InvalidVpcEndpointId.NotFound"]
            if failed:
                raise RuntimeError(f"VPC endpoints of {vpc_id} not deleted: {failed!r}")
        if endpoints:
            return f"endpoints {[e['VpcEndpointId'] for e in endpoints]!r} are deleting"
        interfaces = ec2.describe_network_interfaces(Filters=in_vpc)["NetworkInterfaces"]
        attached = [n["NetworkInterfaceId"] for n in interfaces if n["Status"] != "available"]
        if attached:
            return f"interfaces {attached!r} are still attached"
        for n in interfaces:
            ec2.delete_network_interface(NetworkInterfaceId=n["NetworkInterfaceId"])
        groups = [g for g in ec2.describe_security_groups(Filters=in_vpc)["SecurityGroups"]
                  if g["GroupName"] != "default"]
        for g in groups:
            if g.get("IpPermissions"):
                ec2.revoke_security_group_ingress(GroupId=g["GroupId"], IpPermissions=g["IpPermissions"])
            if g.get("IpPermissionsEgress"):
                ec2.revoke_security_group_egress(
                    GroupId=g["GroupId"], IpPermissions=g["IpPermissionsEgress"])
        for g in groups:
            ec2.delete_security_group(GroupId=g["GroupId"])
        for table in ec2.describe_route_tables(Filters=in_vpc)["RouteTables"]:
            associations = table.get("Associations", [])
            if any(a.get("Main") for a in associations):
                continue
            for a in associations:
                ec2.disassociate_route_table(AssociationId=a["RouteTableAssociationId"])
            ec2.delete_route_table(RouteTableId=table["RouteTableId"])
        for s in ec2.describe_subnets(Filters=in_vpc)["Subnets"]:
            ec2.delete_subnet(SubnetId=s["SubnetId"])
        ec2.delete_vpc(VpcId=vpc_id)
        return ""

    while True:
        try:
            waiting = _teardown_pass()
            if not waiting:
                return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidVpcID.NotFound":
                return
            if code not in _NETWORK_RETRY:
                raise RuntimeError(f"VPC {vpc_id} teardown: {exc}") from exc
            waiting = str(exc)
        if time.monotonic() >= deadline:
            raise RuntimeError(f"VPC {vpc_id} teardown missed the cleanup deadline: {waiting}")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
