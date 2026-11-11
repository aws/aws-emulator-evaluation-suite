"""step-added-while-cluster-starting-queues-then-runs."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "step-added-while-cluster-starting-queues-then-runs"
GROUP = "steps"
SERVICES = ["emr"]

# ===== helpers =====

INSTANCE_TYPE = "m5.xlarge"
RELEASE_LABEL = "emr-6.15.0"

_SCENARIO = "emr-step-queued-before-ready"
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
PRE_READY_STATES = {"STARTING", "BOOTSTRAPPING"}
TERMINAL_STEP_STATES = {"COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"}
TERMINAL_CLUSTER_STATES = {"TERMINATED", "TERMINATED_WITH_ERRORS"}
#: How many identical reads the freeze detector demands while the cluster is still provisioning.
FREEZE_READS = 3


def _gone(fn, *codes):
    """Run a teardown call; return quietly only on the given not-found codes, raise the rest."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in codes:
            raise


def _poll(ctx, probe, predicate, *, timeout_s, description):
    """probe() every 2 s until predicate(result); RAISE on timeout (never return the last value).

    A wait the runner's budget cuts short is no verdict: it raises a not-graded TimeoutError.
    """
    start = time.monotonic()
    left = ctx.time_left()
    cap_s = timeout_s if left is None else max(1.0, min(timeout_s, left - 5.0))
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() - start >= cap_s:
            if cap_s < timeout_s:
                raise TimeoutError(
                    f"the check's time budget ran out after {time.monotonic() - start:.1f}s, "
                    f"before the {timeout_s}s wait for {description} ended; last {last!r}; "
                    "not graded"
                )
            raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")
        time.sleep(2.0)


def _error_code(fn, description):
    """Call fn() expecting a refusal; return the error code. RAISES if the call SUCCEEDS.

    Never returns a falsy sentinel on unexpected success: that would let an over-permissive target
    pass as a code mismatch instead of as the acceptance it was.
    """
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001 — the refusal under test; shape asserted by the caller
        response = getattr(exc, "response", None) or {}
        err = response.get("Error", {})
        return err.get("Code", type(exc).__name__), err.get("Message", str(exc))
    raise AssertionError(f"{description} must be REFUSED, but it succeeded and returned {result!r}")


def _delete_with_retry(fn, attempts=8, delay=15):
    """Run an IAM delete, retrying DeleteConflict while EMR still holds the instance profile."""
    for i in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001 — teardown; re-raised on the last attempt
            if "DeleteConflict" not in str(exc) or i == attempts - 1:
                raise
            time.sleep(delay)


def _ensure_emr_roles(ctx):
    """Create the EMR service role and the EC2 instance profile; returns (service, ec2) names."""
    iam = ctx.client("iam")
    svc_role = ctx.unique_name("sim2real-behav-emrq-svc-")
    ec2_role = ctx.unique_name("sim2real-behav-emrq-ec2-")

    iam.create_role(RoleName=svc_role, AssumeRolePolicyDocument=_EMR_SERVICE_TRUST, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=svc_role)))
    iam.attach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY))

    iam.create_role(RoleName=ec2_role, AssumeRolePolicyDocument=_EC2_TRUST, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=ec2_role)))
    iam.attach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY))

    iam.create_instance_profile(InstanceProfileName=ec2_role, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(
        lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role)))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=ec2_role, RoleName=ec2_role))

    # IAM eventual consistency: wait, bounded, until IAM reports the profile carrying its role.
    # RunJobFlow's own bounded retry covers the remaining propagation to EMR.
    deadline = time.monotonic() + 60
    while not iam.get_instance_profile(InstanceProfileName=ec2_role)["InstanceProfile"]["Roles"]:
        if time.monotonic() >= deadline:
            raise AssertionError(f"instance profile {ec2_role} did not list its role within 60s")
        time.sleep(5)
    return svc_role, ec2_role


def _pick_subnet(ctx):
    """This check's private subnet (see _private_network)."""
    return _private_network(ctx)[1]


def _make_bucket(ctx, s3):
    """Create the scratch/log bucket, registered BEFORE the cluster so LIFO empties it AFTER."""
    bucket = ctx.unique_name("sim2real-behav-emrq-")

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

        _gone(_purge_and_delete, "NoSuchBucket")

    ctx.on_cleanup(_cleanup)
    # us-east-1 is S3's one region that rejects an explicit LocationConstraint for its own region.
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


def _terminate_and_await_teardown(ctx, emr, cluster_id):
    """Terminate and WAIT, RAISING if it never reaches TERMINATED. Idempotent: safe to run again in
    cleanup after the body already did it."""
    _gone(lambda: emr.set_termination_protection(
        JobFlowIds=[cluster_id], TerminationProtected=False), "ValidationException", "InvalidRequestException")
    _gone(lambda: emr.terminate_job_flows(JobFlowIds=[cluster_id]), "InvalidRequestException")
    deadline = min(time.monotonic() + 900, _cleanup_deadline(ctx))
    last = None
    while time.monotonic() < deadline:
        try:
            state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        except Exception as exc:  # noqa: BLE001 — teardown classification only
            if _cluster_is_gone(exc):
                return
            last = exc
            time.sleep(2)
            continue
        last = state
        if state in TERMINAL_CLUSTER_STATES:
            return
        time.sleep(2)
    raise AssertionError(f"cluster {cluster_id} did not reach a terminal state within 900s; last {last!r}")


def _run_cluster(emr, ctx, service_role, job_flow_role, **params):
    """RunJobFlow, retrying only transient IAM-propagation / throttle errors."""
    left = ctx.time_left()
    deadline = time.monotonic() + (320.0 if left is None else min(320.0, left))
    while True:
        try:
            resp = emr.run_job_flow(ServiceRole=service_role, JobFlowRole=job_flow_role, **params)
            break
        except Exception as exc:  # noqa: BLE001 — classified below, re-raised if fatal
            low = str(exc).lower()
            transient = ("throttl" in low or "rate exceeded" in low
                         or "invalid instanceprofile" in low or "invalid ec2" in low)
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    cluster_id = resp["JobFlowId"]
    ctx.on_cleanup(lambda: _terminate_and_await_teardown(ctx, emr, cluster_id))
    return cluster_id


def _list_step_ids(emr, cluster_id):
    """Every step id on the cluster, paginated (a membership claim on page one is not a claim)."""
    return {s["Id"] for page in emr.get_paginator("list_steps").paginate(ClusterId=cluster_id)
            for s in page["Steps"]}


# ===== end helpers =====


@tags(
    "axis:happy-path",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """AddJobFlowSteps queues a step submitted while the cluster is still provisioning (STARTING or
    BOOTSTRAPPING) in PENDING with no Timeline.StartDateTime until ready, then runs it; the same
    call is refused once the cluster is TERMINATED, adding nothing.

    Reference: https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-overview.html
    """
    emr = ctx.client("emr")
    s3 = ctx.client("s3")

    bucket = _make_bucket(ctx, s3)
    service_role, job_flow_role = _ensure_emr_roles(ctx)
    subnet = _pick_subnet(ctx)

    # Launched with NO steps, so the step under test is unambiguously one this check submitted into
    # a still-provisioning cluster.
    cluster_id = _run_cluster(
        emr, ctx, service_role, job_flow_role,
        Name=ctx.unique_name("sim2real-behav-emrq-"),
        ReleaseLabel=RELEASE_LABEL,
        LogUri=f"s3://{bucket}/logs/",
        Applications=[{"Name": "Hadoop"}],
        Instances={
            "InstanceGroups": [{
                "Name": "sim2real-primary", "InstanceRole": "MASTER",
                "InstanceType": INSTANCE_TYPE, "InstanceCount": 1, "Market": "ON_DEMAND",
            }],
            "KeepJobFlowAliveWhenNoSteps": True,
            "TerminationProtected": False,
            "Ec2SubnetId": subnet,
        },
        VisibleToAllUsers=True,
        Tags=_TAGS,
    )

    assert not _list_step_ids(emr, cluster_id), (
        f"a cluster launched with no Steps must list none; got "
        f"{sorted(_list_step_ids(emr, cluster_id))!r}"
    )

    # --- the premise, asserted rather than assumed: the cluster has not finished provisioning.
    # A target that is already WAITING here has not provisioned anything, which is itself the
    # divergence this check is for.
    at_submit = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
    assert at_submit in PRE_READY_STATES, (
        f"the step must be submitted while the cluster is still provisioning; DescribeCluster "
        f"reported {at_submit!r} immediately after RunJobFlow, expected one of "
        f"{sorted(PRE_READY_STATES)}. Real EC2 provisioning cannot complete this fast."
    )

    nonce = ctx.unique_name("queued-step-")
    output_key = f"steps/{nonce}"
    step_script = (
        f"set -eu; printf '%s' '{nonce}' > /tmp/{nonce}; "
        f"aws s3 cp /tmp/{nonce} s3://{bucket}/{output_key} --region {ctx.region}"
    )
    added = emr.add_job_flow_steps(
        JobFlowId=cluster_id,
        Steps=[{
            "Name": "sim2real-behav-emrq-queued",
            "ActionOnFailure": "CONTINUE",
            "HadoopJarStep": {"Jar": "command-runner.jar", "Args": ["bash", "-c", step_script]},
        }],
    )
    step_ids = added["StepIds"]
    assert len(step_ids) == 1, (
        f"AddJobFlowSteps must return exactly one step id for one submitted step, got {step_ids!r}"
    )
    step_id = step_ids[0]

    # --- Freeze detector: while the cluster is still provisioning, the step must not move.
    # No timing assumption — only that repeated reads agree and that reading does not advance state.
    frozen = []
    freeze_deadline = time.monotonic() + 300
    while len(frozen) < FREEZE_READS:
        assert time.monotonic() < freeze_deadline, (
            f"could not collect {FREEZE_READS} reads of step {step_id} while cluster {cluster_id} "
            f"was still in {sorted(PRE_READY_STATES)}; observations so far {frozen!r}"
        )
        state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        assert state in PRE_READY_STATES, (
            f"the cluster left {sorted(PRE_READY_STATES)} (now {state!r}) after only {len(frozen)} "
            f"of {FREEZE_READS} reads — provisioning a real EC2 fleet cannot finish that fast, so "
            f"the queued-step window was never observable. Observations: {frozen!r}"
        )
        status = emr.describe_step(ClusterId=cluster_id, StepId=step_id)["Step"]["Status"]
        frozen.append((status["State"], sorted(status["Timeline"])))
        time.sleep(2.0)

    assert [f[0] for f in frozen] == ["PENDING"] * FREEZE_READS, (
        f"a step submitted to a still-provisioning cluster must sit in PENDING, unchanged across "
        f"{FREEZE_READS} reads; observed {frozen!r}"
    )
    assert all("StartDateTime" not in keys for _, keys in frozen), (
        f"a PENDING step has not started, so it must carry no Timeline.StartDateTime; observed "
        f"{frozen!r}"
    )
    assert all("CreationDateTime" in keys for _, keys in frozen), (
        f"a queued step must still record when it was SUBMITTED; observed {frozen!r}"
    )

    # --- it then really runs. Terminal assertion is an independent read at S3, of bytes only a
    # real execution of the customer's command could have produced.
    step = _poll(
        ctx,
        lambda: emr.describe_step(ClusterId=cluster_id, StepId=step_id)["Step"],
        lambda s: s["Status"]["State"] in TERMINAL_STEP_STATES,
        timeout_s=1500,
        description=f"the queued step {step_id} reaches a terminal state",
    )
    assert step["Status"]["State"] == "COMPLETED", (
        f"the queued step must eventually run to COMPLETED once the cluster is ready; got "
        f"{step['Status']['State']!r} (reason {step['Status'].get('StateChangeReason')!r})"
    )
    body = s3.get_object(Bucket=bucket, Key=output_key)["Body"].read()
    assert body == nonce.encode("utf-8"), (
        f"the queued step must actually have executed: expected {nonce!r} at "
        f"s3://{bucket}/{output_key}, read back {body!r}"
    )

    cluster_ready = emr.describe_cluster(
        ClusterId=cluster_id)["Cluster"]["Status"]["Timeline"].get("ReadyDateTime")
    assert cluster_ready is not None, (
        "a cluster that ran a step must carry Timeline.ReadyDateTime"
    )
    created = step["Status"]["Timeline"].get("CreationDateTime")
    started = step["Status"]["Timeline"].get("StartDateTime")
    assert created is not None and started is not None, (
        f"an executed step must carry both CreationDateTime and StartDateTime, got "
        f"{step['Status']['Timeline']!r}"
    )
    assert created <= cluster_ready <= started, (
        f"the step was submitted BEFORE the cluster was ready and started AFTER it: expected "
        f"created({created}) <= ready({cluster_ready}) <= started({started})"
    )

    # --- the other end of the documented window. Break exactly one thing: terminate the cluster.
    # Done in the body, not cleanup: a cut-off cleanup passes while leaking.
    ids_before = _list_step_ids(emr, cluster_id)
    emr.terminate_job_flows(JobFlowIds=[cluster_id])
    final = _poll(
        ctx,
        lambda: emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"],
        lambda s: s in TERMINAL_CLUSTER_STATES,
        timeout_s=900,
        description=f"cluster {cluster_id} reaches a terminal state after TerminateJobFlows",
    )
    assert final == "TERMINATED", (
        f"a cluster terminated by request after a successful step must reach TERMINATED, got "
        f"{final!r}"
    )

    code, message = _error_code(
        lambda: emr.add_job_flow_steps(
            JobFlowId=cluster_id,
            Steps=[{
                "Name": "sim2real-behav-emrq-after-death",
                "ActionOnFailure": "CONTINUE",
                "HadoopJarStep": {
                    "Jar": "command-runner.jar",
                    "Args": ["bash", "-c", "printf never"],
                },
            }],
        ),
        f"AddJobFlowSteps on TERMINATED cluster {cluster_id}",
    )
    expected_message = "A job flow that is shutting down, terminated, or finished may not be modified."
    assert (code, message) == ("ValidationException", expected_message), (
        f"adding a step to a TERMINATED cluster must be refused with ValidationException "
        f"{expected_message!r}, got {code!r} ({message!r})"
    )

    # --- effect absent, via an independent read: the refused step was never recorded.
    ids_after = _poll(
        ctx,
        lambda: _list_step_ids(emr, cluster_id),
        lambda ids: ids == ids_before,
        timeout_s=300,
        description=f"the step list of terminated cluster {cluster_id} settles to what it was",
    )
    assert ids_after == ids_before, (
        f"a refused AddJobFlowSteps must add no step: before {sorted(ids_before)!r}, after "
        f"{sorted(ids_after)!r}"
    )
    names = {s["Name"] for page in emr.get_paginator("list_steps").paginate(ClusterId=cluster_id)
             for s in page["Steps"]}
    assert "sim2real-behav-emrq-after-death" not in names, (
        f"the refused step must not appear in ListSteps under any state; ListSteps names are "
        f"{sorted(names)!r}"
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
