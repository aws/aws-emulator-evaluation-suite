"""bootstrap-action-failure-terminates-with-errors."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "bootstrap-action-failure-terminates-with-errors"
GROUP = 'cluster-lifecycle'
SERVICES = ['emr']

# ===== helpers =====

INSTANCE_TYPE = "m5.xlarge"
RELEASE_LABEL = "emr-6.15.0"

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
        "Effect": "Allow",
        "Principal": {"Service": "ec2.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
# The v1 service policy, deliberately, NOT AmazonEMRServicePolicy_v2: v2 only grants EMR access
# to network resources carrying the `for-use-with-amazon-emr-managed-policies` tag, which the
# check's own VPC does not carry.
_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"
IDLE_TIMEOUT_S = 60

MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

TERMINAL_CLUSTER_STATES = {"TERMINATED", "TERMINATED_WITH_ERRORS"}


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


def _poll(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _cluster_state(emr, cluster_id):
    return emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]


def _register_cluster_cleanup(ctx, emr, cluster_id) -> None:
    """Register teardown for cluster_id. MUST be called before the id is used."""

    def _cleanup() -> None:
        _swallow(
            lambda: emr.set_termination_protection(
                JobFlowIds=[cluster_id], TerminationProtected=False
            )
        )
        _swallow(lambda: emr.terminate_job_flows(JobFlowIds=[cluster_id]))
        _poll(
            lambda: _cluster_state(emr, cluster_id),
            lambda s: s in TERMINAL_CLUSTER_STATES,
            timeout_s=600,
            interval_s=2,
            description=f"cluster {cluster_id} reaches a terminal state",
        )

    ctx.on_cleanup(_cleanup)


def _make_bucket(ctx, s3):
    """Create a bucket for the bootstrap script and register recursive teardown.

    Registered BEFORE the cluster so the LIFO cleanup order terminates the cluster
    first — the bootstrap script object stays referenced until then.
    """
    bucket = ctx.unique_name("sim2real-behav-emr-boot-")

    def _cleanup() -> None:
        def _purge_and_delete() -> None:
            paginator = s3.get_paginator("list_object_versions")
            for page in paginator.paginate(Bucket=bucket):
                victims = [
                    {"Key": o["Key"], "VersionId": o["VersionId"]}
                    for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
                ]
                if victims:
                    failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": victims}).get("Errors")
                    if failed:
                        raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            s3.delete_bucket(Bucket=bucket)

        _swallow(_purge_and_delete)

    ctx.on_cleanup(_cleanup)
    # S3's own quirk, not a pin on this check's region: CreateBucket rejects an explicit
    # LocationConstraint of us-east-1 (its API default), so it must be omitted there and
    # supplied for every other region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    return bucket


def _delete_with_retry(fn, attempts=6, delay=10):
    """Run an IAM delete, retrying DeleteConflict.

    Even once the cluster reports TERMINATED, IAM can briefly still see the instance
    profile as in use, so the delete is retried rather than leaking the role.
    """
    for i in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001
            if "DeleteConflict" not in str(exc) or i == attempts - 1:
                raise
            time.sleep(delay)


def _ensure_emr_roles(ctx):
    """Create the service role and EC2 instance profile EMR needs, and register their
    teardown. Returns (service_role, ec2_role)."""

    iam = ctx.client("iam")
    svc_role = ctx.unique_name("sim2real-behav-emr-svc-")
    ec2_role = ctx.unique_name("sim2real-behav-emr-ec2-")
    # Cleanups run LIFO, so registering each teardown immediately after its create yields the
    # only order IAM accepts: remove-from-profile, delete profile, detach policies, delete roles.
    try:
        iam.create_role(RoleName=svc_role, AssumeRolePolicyDocument=_EMR_SERVICE_TRUST)
        ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=svc_role)))
        iam.attach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY))

        iam.create_role(RoleName=ec2_role, AssumeRolePolicyDocument=_EC2_TRUST)
        ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=ec2_role)))
        iam.attach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY))

        # RunJobFlow's JobFlowRole is an INSTANCE PROFILE name, not a role name; give it the
        # same name as its role, which is the convention EMR's own default roles follow.
        iam.create_instance_profile(InstanceProfileName=ec2_role)
        ctx.on_cleanup(lambda: _delete_with_retry(
            lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role)))
        iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
        ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=ec2_role, RoleName=ec2_role))
    except Exception as exc:  # noqa: BLE001
        # Can't attribute anything to EMR if we couldn't even build its prerequisites — an
        # honest skip, not a mystery RunJobFlow ValidationException.
        raise AssertionError(
            f"cannot provision the EMR service role / EC2 instance profile: {exc}"
        ) from exc

    # IAM is eventually consistent; EMR rejects a role/profile it cannot see yet.
    # _launch_cluster's own retry loop is the bounded wait for that: it classifies
    # "invalid InstanceProfile" / "invalid EC2" as transient and retries with a stated
    # deadline (16 attempts, 20s apart), so no unconditional sleep is needed here.
    return svc_role, ec2_role


def _launch_cluster(
    ctx, emr, *, keep_alive: bool, service_role: str, job_flow_role: str, steps=None, **overrides
):
    """RunJobFlow the cheapest cluster that can prove a data-plane invariant."""
    name = ctx.unique_name("sim2real-behav-emr-cluster-")
    params = dict(
        Name=name,
        ReleaseLabel=RELEASE_LABEL,
        Instances={
            "InstanceGroups": [
                {
                    "Name": "Primary",
                    "InstanceRole": "MASTER",
                    "InstanceType": INSTANCE_TYPE,
                    "InstanceCount": 1,
                    "Market": "ON_DEMAND",
                }
            ],
            "Ec2SubnetId": _private_network(ctx, INSTANCE_TYPE)[1],
            "KeepJobFlowAliveWhenNoSteps": keep_alive,
            "TerminationProtected": False,
        },
        Applications=[{"Name": "Hadoop"}],
        JobFlowRole=job_flow_role,
        ServiceRole=service_role,
        VisibleToAllUsers=True,
        Tags=MANAGED_TAGS,
        AutoTerminationPolicy={"IdleTimeout": IDLE_TIMEOUT_S},
    )
    if steps is not None:
        params["Steps"] = steps
    params.update(overrides)

    left = ctx.time_left()
    deadline = time.monotonic() + (320 if left is None else min(320, left))
    while True:
        try:
            resp = emr.run_job_flow(**params)
            break
        except Exception as exc:  # noqa: BLE001 — classified below, re-raised if fatal
            lowered = str(exc).lower()
            transient = (
                "throttl" in lowered
                or "rate exceeded" in lowered
                or "invalid instanceprofile" in lowered
                or "invalid ec2" in lowered
            )
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(2)

    cluster_id = resp["JobFlowId"]
    _register_cluster_cleanup(ctx, emr, cluster_id)  # BEFORE the id is used anywhere
    return cluster_id, name


# ===== end helpers =====


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A bootstrap action that exits non-zero fails the whole cluster: TERMINATED_WITH_ERRORS with
    StateChangeReason.Code BOOTSTRAP_FAILURE, no ReadyDateTime, and the submitted step CANCELLED
    rather than run."""
    emr = ctx.client("emr")
    s3 = ctx.client("s3")
    # Registered first, so LIFO tears the cluster down before the IAM roles it assumes.
    service_role, job_flow_role = _ensure_emr_roles(ctx)

    bucket = _make_bucket(ctx, s3)
    script_key = "bootstrap/fail.sh"
    s3.put_object(
        Bucket=bucket,
        Key=script_key,
        Body=b"#!/bin/bash\necho sim2real-bootstrap-deliberate-failure >&2\nexit 17\n",
    )

    step_name = "sim2real-behav-emr-step-that-must-not-run"
    cluster_id, _ = _launch_cluster(
        ctx,
        emr,
        keep_alive=True,
        service_role=service_role,
        job_flow_role=job_flow_role,
        steps=[
            {
                "Name": step_name,
                "ActionOnFailure": "CONTINUE",
                "HadoopJarStep": {
                    "Jar": "command-runner.jar",
                    "Args": ["bash", "-c", "exit 0"],
                },
            }
        ],
        BootstrapActions=[
            {
                "Name": "sim2real-behav-emr-failing-bootstrap",
                "ScriptBootstrapAction": {"Path": f"s3://{bucket}/{script_key}"},
            }
        ],
    )

    # RunJobFlow must have recorded the bootstrap action verbatim.
    actions = emr.list_bootstrap_actions(ClusterId=cluster_id)["BootstrapActions"]
    assert len(actions) == 1, f"expected the one submitted bootstrap action, got {actions!r}"
    assert actions[0]["ScriptPath"] == f"s3://{bucket}/{script_key}", (
        f"ListBootstrapActions must echo the submitted ScriptPath, got {actions[0]!r}"
    )

    final = _poll(
        lambda: _cluster_state(emr, cluster_id),
        lambda s: s in TERMINAL_CLUSTER_STATES,
        timeout_s=1500,
        interval_s=20,
        description=f"cluster {cluster_id} reaches a terminal state",
    )
    cluster = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]
    assert final == "TERMINATED_WITH_ERRORS", (
        f"a failing bootstrap action must end the cluster in TERMINATED_WITH_ERRORS, "
        f"got {final!r} (reason: {cluster['Status'].get('StateChangeReason')!r})"
    )

    reason = cluster["Status"]["StateChangeReason"]
    assert reason.get("Code") == "BOOTSTRAP_FAILURE", (
        f"a non-zero bootstrap action must be classified BOOTSTRAP_FAILURE, got {reason!r}"
    )
    assert reason.get("Message"), (
        f"StateChangeReason must carry a human-readable Message, got {reason!r}"
    )

    # A cluster that failed to bootstrap never became ready.
    timeline = cluster["Status"]["Timeline"]
    assert "ReadyDateTime" not in timeline, (
        f"a bootstrap-failed cluster must never report ReadyDateTime, got {timeline!r}"
    )
    assert "EndDateTime" in timeline, (
        f"a terminal cluster must report Status.Timeline.EndDateTime, got {timeline!r}"
    )

    # ...and the step must have been cancelled, not executed.
    steps = _poll(
        lambda: emr.list_steps(ClusterId=cluster_id)["Steps"],
        lambda ss: bool(ss)
        and all(
            s["Status"]["State"] in {"COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"}
            for s in ss
        ),
        timeout_s=300,
        interval_s=15,
        description=f"the step on {cluster_id} reaches a terminal state",
    )
    assert len(steps) == 1, f"expected the one submitted step, got {steps!r}"
    assert steps[0]["Name"] == step_name, f"unexpected step {steps[0]!r}"
    assert steps[0]["Status"]["State"] == "CANCELLED", (
        f"a step on a bootstrap-failed cluster must be CANCELLED, never run; got "
        f"{steps[0]['Status']['State']!r}"
    )
    assert "StartDateTime" not in steps[0]["Status"]["Timeline"], (
        f"a cancelled step must have no StartDateTime, got {steps[0]['Status']['Timeline']!r}"
    )


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
