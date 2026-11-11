"""emr-step-concurrency-level-two-runs-two-steps-with-overlapping-intervals."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "emr-step-concurrency-level-two-runs-two-steps-with-overlapping-intervals"
GROUP = 'concurrency'
SERVICES = ['emr']

# ===== helpers =====

INSTANCE_TYPE = "m5.xlarge"
RELEASE_LABEL = "emr-6.15.0"

# Each step holds the cluster for this long before writing its marker. The number is never
# asserted against -- only the RELATION between two observed intervals is -- so it exists purely to
# make the two intervals wide enough that a scheduler running them together cannot look like a
# scheduler running them one after the other.
_STEP_HOLD_S = 90

_SCENARIO = "emr-step-concurrency"
_TAGS = [{"Key": "sim2real", "Value": _SCENARIO},
         {"Key": "sim2real:managed", "Value": "true"},
         {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]

_EMR_SERVICE_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow",
                   "Principal": {"Service": "elasticmapreduce.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})
_EC2_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})
_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"

_STEP_TERMINAL = {"COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED",
                  "TERMINATED_WITH_ERRORS", "INTERNAL_ERROR"}
_CLUSTER_GONE_CODES = ("InvalidRequestException", "ClusterNotFound",
                       "ResourceNotFoundException", "EntityNotFoundException")


def _ignore_not_found(fn):
    """Run a teardown call: a resource that is already gone is fine, any other error raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "NoSuchBucket", "InvalidGroup.NotFound", "InvalidPermission.NotFound"
        ):
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


def _delete_with_retry(fn, attempts=8, delay=15):
    """Run an IAM delete, retrying DeleteConflict."""
    for i in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001
            if "DeleteConflict" not in str(exc) or i == attempts - 1:
                raise
            time.sleep(delay)


def _ensure_emr_roles(ctx):
    """Create the EMR service role and the EC2 instance profile. Returns (service_role, ec2_role).

    EMR_DefaultRole and EMR_EC2_DefaultRole do NOT exist in a fresh account, so
    pointing at them would surface as an untagged ClientError rather than as EMR behaviour.
    """
    iam = ctx.client("iam")
    svc_role = ctx.unique_name("sim2real-behav-emr-conc-svc-")
    ec2_role = ctx.unique_name("sim2real-behav-emr-conc-ec2-")

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

    # No unconditional sleep here for IAM -> EMR/EC2 propagation: _run_cluster already retries
    # RunJobFlow on the specific transient errors that propagation delay produces, with its own
    # bounded deadline and a stated reason, so a second fixed wait would be redundant.
    return svc_role, ec2_role


def _pick_subnet(ctx, run_state: dict):
    """This check's private subnet (see _private_network)."""
    return _private_network(ctx, run_state)[1]


def _make_bucket(ctx, s3):
    """Create the scratch/log bucket. Registered BEFORE the cluster so LIFO empties it AFTER the
    cluster is gone -- EMR keeps writing step logs into LogUri right up to termination."""
    bucket = ctx.unique_name("sim2real-behav-emr-conc-")

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

        _ignore_not_found(_purge_and_delete)

    ctx.on_cleanup(_cleanup)
    if ctx.region == "us-east-1":
        # S3 CreateBucket rejects an explicit LocationConstraint of "us-east-1" -- the literal
        # here is the API's own quirk, not a pinned target region; the bucket still always lands
        # in ctx.region.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})
    return bucket


def _cluster_is_gone(exc):
    """True only for the error that means the cluster no longer exists."""
    code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
    return code in _CLUSTER_GONE_CODES or "is not valid" in str(exc)


def _terminate_and_await_teardown(ctx, run_state: dict, emr, cluster_id):
    """Terminate the cluster and WAIT, so the IAM deletions registered earlier (and therefore
    running later, LIFO) do not race a cluster still assuming the service role."""
    try:
        emr.terminate_job_flows(JobFlowIds=[cluster_id])
    except ClientError as exc:
        if _cluster_is_gone(exc):
            return
        state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        if state not in ("TERMINATED", "TERMINATED_WITH_ERRORS"):
            raise
        return
    deadline = min(time.monotonic() + 600, _cleanup_deadline(ctx, run_state))
    while True:
        try:
            state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        except ClientError as exc:
            if _cluster_is_gone(exc):
                return
            raise
        if state in ("TERMINATED", "TERMINATED_WITH_ERRORS"):
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"EMR cluster {cluster_id} did not terminate within 600 s (last {state})")
        time.sleep(2)


def _run_cluster(emr, ctx, run_state: dict, service_role, job_flow_role, **params):
    """RunJobFlow, retrying only the transient IAM-propagation / throttle errors, with teardown
    registered immediately after the id exists."""
    left = ctx.time_left()
    deadline = time.monotonic() + (320 if left is None else min(320, left))
    while True:
        try:
            resp = emr.run_job_flow(ServiceRole=service_role, JobFlowRole=job_flow_role, **params)
            break
        except Exception as exc:  # noqa: BLE001
            low = str(exc).lower()
            transient = ("throttl" in low or "rate exceeded" in low
                         or "invalid instanceprofile" in low or "invalid ec2" in low
                         or "failed to authorize instance profile" in low)
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    cluster_id = resp["JobFlowId"]
    ctx.on_cleanup(
        lambda: _terminate_and_await_teardown(ctx, run_state, emr, cluster_id))
    return cluster_id


def _shell_step(name, script):
    """A step that runs `script` through bash on the primary node via command-runner.jar.

    command-runner.jar execs its argv directly with no shell, so a redirect or a `&&` only works
    inside an explicit `bash -c`.
    """
    return {"Name": name, "ActionOnFailure": "CONTINUE",
            "HadoopJarStep": {"Jar": "command-runner.jar",
                              "Args": ["bash", "-c", script]}}


# ===== end helpers =====


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c3", "cap:c5")
def run(ctx) -> None:
    """At StepConcurrencyLevel 2 two steps' observed run intervals overlap; after ModifyCluster sets
    it to 1 on the same cluster they are disjoint and ordered, with every step's S3 marker present
    so serialisation is not achieved by dropping work. Only observed intervals are compared.
    """
    # Per-run state: the teardown deadline, the private network and the clusters placed in it.
    run_state: dict = {}
    emr = ctx.client("emr")
    s3 = ctx.client("s3")

    service_role, job_flow_role = _ensure_emr_roles(ctx)
    subnet = _pick_subnet(ctx, run_state)
    bucket = _make_bucket(ctx, s3)

    def _hold_and_write(key, nonce):
        return (f"set -e; sleep {_STEP_HOLD_S}; printf '%s' {nonce} > /tmp/{nonce}; "
                f"aws s3 cp /tmp/{nonce} s3://{bucket}/{key} --region {ctx.region}")

    cluster_id = _run_cluster(
        emr, ctx, run_state, service_role, job_flow_role,
        Name=ctx.unique_name("sim2real-behav-emr-conc-"),
        ReleaseLabel=RELEASE_LABEL,
        LogUri=f"s3://{bucket}/logs/",
        StepConcurrencyLevel=2,
        Instances={"InstanceCount": 1, "MasterInstanceType": INSTANCE_TYPE,
                   "KeepJobFlowAliveWhenNoSteps": True, "TerminationProtected": False,
                   "Ec2SubnetId": subnet},
        Applications=[{"Name": "Hadoop"}],
        VisibleToAllUsers=True,
        Tags=_TAGS,
    )

    def _cluster():
        return emr.describe_cluster(ClusterId=cluster_id)["Cluster"]

    waiting = _poll(lambda: _cluster()["Status"]["State"],
                    lambda s: s not in ("STARTING", "BOOTSTRAPPING"),
                    timeout_s=1000, interval_s=20,
                    description=f"EMR cluster {cluster_id} finishing provisioning")
    assert waiting == "WAITING", (
        f"a keep-alive cluster with no steps must settle in WAITING before the steps are added; "
        f"got {waiting!r}"
    )
    assert _cluster().get("StepConcurrencyLevel") == 2, (
        f"the cluster must report the StepConcurrencyLevel it was launched with; got "
        f"{_cluster().get('StepConcurrencyLevel')!r}"
    )

    def _timelines(step_ids):
        out = {}
        for sid in step_ids:
            status = emr.describe_step(ClusterId=cluster_id, StepId=sid)["Step"]["Status"]
            out[sid] = (status["State"], status.get("Timeline") or {})
        return out

    def _run_pair(phase, nonces):
        keys = [f"markers/{phase}-{i}" for i in (1, 2)]
        ids = emr.add_job_flow_steps(
            JobFlowId=cluster_id,
            Steps=[_shell_step(f"sim2real-conc-{phase}-{i}", _hold_and_write(k, n))
                   for i, (k, n) in enumerate(zip(keys, nonces), start=1)],
        )["StepIds"]
        assert len(ids) == 2, (
            f"AddJobFlowSteps must return one id per submitted step, got {ids!r}"
        )
        final = _poll(lambda: _timelines(ids),
                      lambda m: all(st in _STEP_TERMINAL for st, _ in m.values()),
                      timeout_s=900, interval_s=15,
                      description=f"both {phase} steps on {cluster_id} reaching terminal states")
        for sid, (state, _tl) in final.items():
            assert state == "COMPLETED", (
                f"every {phase} step must reach COMPLETED -- serialisation must not be achieved by "
                f"dropping work -- step {sid} ended {state!r} (all: {final!r})"
            )
        for key, nonce in zip(keys, nonces):
            body = s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode("utf-8")
            assert body == nonce, (
                f"the {phase} step's command must have written its own nonce to "
                f"s3://{bucket}/{key}; expected {nonce!r}, got {body!r}"
            )
        intervals = []
        for sid, (_state, tl) in final.items():
            start, end = tl.get("StartDateTime"), tl.get("EndDateTime")
            assert start is not None and end is not None, (
                f"a COMPLETED step must carry both StartDateTime and EndDateTime so its interval "
                f"is observable; step {sid} had {tl!r}"
            )
            intervals.append((sid, start, end))
        intervals.sort(key=lambda t: t[1])
        return intervals

    # ---- phase 1, at concurrency 2: the intervals must OVERLAP -----------------------------------
    (a_id, a_start, a_end), (b_id, b_start, b_end) = _run_pair(
        "conc2", [ctx.unique_name("conc2-a-"), ctx.unique_name("conc2-b-")])
    assert a_start < b_end and b_start < a_end, (
        f"at StepConcurrencyLevel 2 the two steps must run at the same time, so their intervals "
        f"must overlap.\n  {a_id}: [{a_start!r}, {a_end!r}]\n  {b_id}: [{b_start!r}, {b_end!r}]"
    )

    # ---- the only thing that changes: the concurrency level --------------------------------------
    modified = emr.modify_cluster(ClusterId=cluster_id, StepConcurrencyLevel=1)
    assert modified.get("StepConcurrencyLevel") == 1, (
        f"ModifyCluster must return the level it was asked to set, got {modified!r}"
    )
    assert _cluster().get("StepConcurrencyLevel") == 1, (
        f"DescribeCluster must reflect the modified StepConcurrencyLevel; got "
        f"{_cluster().get('StepConcurrencyLevel')!r}"
    )

    # ---- phase 2, at concurrency 1: the intervals must be DISJOINT and ordered --------------------
    (c_id, c_start, c_end), (d_id, d_start, d_end) = _run_pair(
        "conc1", [ctx.unique_name("conc1-c-"), ctx.unique_name("conc1-d-")])
    assert d_start >= c_end, (
        f"at StepConcurrencyLevel 1 the second step must not start before the first has ended, so "
        f"the intervals must be disjoint and ordered.\n  {c_id}: [{c_start!r}, {c_end!r}]\n"
        f"  {d_id}: [{d_start!r}, {d_end!r}]"
    )


# ===== private network =====
#: The check's own VPC: its clusters sit in a subnet with no internet route, and a gateway
#: endpoint to S3 (all EMR needs there) is the only way out.
_PRIVATE_VPC_CIDR = "10.0.0.0/16"
_PRIVATE_SUBNET_CIDR = "10.0.0.0/24"
#: The suite's 900 s cleanup budget less a margin: one deadline per run, started by the first
#: teardown that asks for it; every teardown wait of the run is cut to it.
_CLEANUP_BUDGET_S = 840.0
_NETWORK_RETRY = frozenset({
    "DependencyViolation", "InvalidGroup.NotFound", "InvalidPermission.NotFound",
    "InvalidSubnetID.NotFound", "InvalidNetworkInterfaceID.NotFound",
})


def _private_network(ctx, run_state: dict, instance_type: str = "m5.xlarge") -> tuple[str, str]:
    """(vpc_id, subnet_id) of this check's private network, created on first use in a zone that
    offers instance_type; its teardown is registered before any cluster is placed in it."""
    if "network" in run_state:
        return run_state["network"]
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
    ctx.on_cleanup(lambda: _drop_private_network(ctx, run_state, vpc_id))
    ctx.client("emr").meta.events.register(
        "after-call.emr.RunJobFlow", lambda parsed, **_: _track_cluster(ctx, run_state, parsed.get("JobFlowId")))
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
    run_state["network"] = (vpc_id, subnet_id)
    return vpc_id, subnet_id


def _cleanup_deadline(ctx, run_state: dict) -> float:
    """The run's one teardown deadline, started by the first teardown that asks for it."""
    return run_state.setdefault("deadline", time.monotonic() + _CLEANUP_BUDGET_S)


def _track_cluster(ctx, run_state: dict, cluster_id) -> None:
    """Record a cluster this check created, so the network teardown waits for it to terminate."""
    if cluster_id:
        run_state.setdefault("clusters", set()).add(cluster_id)


def _drop_private_network(ctx, run_state: dict, vpc_id: str) -> None:
    """Delete the check's VPC: wait for its EMR clusters to terminate, delete its endpoints, wait for
    its interfaces to release, clear then delete every non-default group (EMR's reference each other),
    route tables, subnets, the VPC. Retries in-use refusals every 2 s to the run's cleanup deadline."""
    from botocore.exceptions import ClientError

    run_state.pop("network", None)
    created = run_state.pop("clusters", set())
    ec2 = ctx.client("ec2")
    emr = ctx.client("emr")
    in_vpc = [{"Name": "vpc-id", "Values": [vpc_id]}]
    deadline = _cleanup_deadline(ctx, run_state)

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
