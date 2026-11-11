"""emr-run-step-spark."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

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
# AmazonElasticMapReduceRole, not AmazonEMRServicePolicy_v2: v2 only grants EMR access to network
# resources carrying the `for-use-with-amazon-emr-managed-policies` tag.
_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
# Grants the cluster's EC2 instances S3 access — which is what makes the round-trip below possible:
# the instances read the PySpark script from S3 and write the job's result back to it.
_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"

MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

# A native data-plane FAIL marker: a check detail carrying it is scored as a fidelity `fail`.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

# The job the cluster actually runs. Deterministic distributed compute — sum of squares 1..N spread
# over 4 partitions — written back to S3 as text. The expected value is closed-form
# (N(N+1)(2N+1)/6), so the caller asserts the EXACT number Spark computed instead of trusting a
# control-plane status string. A backend that fabricates a COMPLETED step without running Spark
# produces no output object and is caught.
_SPARK_JOB = '''\
import sys

from pyspark.sql import SparkSession

spark = SparkSession.builder.appName("sim2real-emr-dataplane").getOrCreate()
n = int(sys.argv[1])
out = sys.argv[2]
total = spark.sparkContext.parallelize(range(1, n + 1), 4).map(lambda x: x * x).sum()
spark.sparkContext.parallelize(["%d,%d" % (n, total)], 1).saveAsTextFile(out)
spark.stop()
'''

# The harness's per-check budget for this suite: every wait ends only where the runner would
# stop the check anyway, so no wait is an assertion on elapsed time.
_SUITE_BUDGET_S = 1800

_JOB_N = 100
_JOB_EXPECTED = _JOB_N * (_JOB_N + 1) * (2 * _JOB_N + 1) // 6  # 338350
_JOB_KEY = "job/sum_squares.py"
_OUT_PREFIX = "out"


def _dp_fail(msg: str) -> None:
    """Raise a native data-plane fidelity FAIL."""
    raise AssertionError(f"{DATAPLANE_MARKER}: {msg}")


def _unique_name(prefix=""):
    return f"sim2real-behav-{prefix}{uuid.uuid4().hex[:8]}"


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    import time as _t
    deadline = _t.monotonic() + timeout_s
    last = None
    while _t.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        _t.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _ensure_emr_roles(ctx):
    """Create the service role + EC2 instance profile EMR needs. Returns (service_role, ec2_role).

    The check owns its IAM prerequisites on every target rather than assuming account-level roles.
    """
    iam = ctx.client("iam")
    svc_role = _unique_name("emr-svc-")
    ec2_role = _unique_name("emr-ec2-")
    # Cleanups run LIFO, so registering each teardown immediately after its create yields the only
    # order IAM accepts: remove-from-profile, delete profile, detach policies, delete roles.
    try:
        iam.create_role(RoleName=svc_role, AssumeRolePolicyDocument=_EMR_SERVICE_TRUST)
        ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=svc_role)))
        iam.attach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY))

        iam.create_role(RoleName=ec2_role, AssumeRolePolicyDocument=_EC2_TRUST)
        ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=ec2_role)))
        iam.attach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY))

        # RunJobFlow's JobFlowRole is an INSTANCE PROFILE name, not a role name; give it the same
        # name as its role, which is the convention EMR's own default roles follow.
        iam.create_instance_profile(InstanceProfileName=ec2_role)
        ctx.on_cleanup(lambda: _delete_with_retry(
            lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role)))
        iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
        ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=ec2_role, RoleName=ec2_role))
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(
            f"cannot provision the EMR service role / EC2 instance profile: {exc}"
        ) from exc

    # IAM is eventually consistent; EMR rejects a role/profile it cannot see yet. RunJobFlow
    # also retries "invalid InstanceProfile" below, so this only shortens the retry loop —
    # wait on the actual condition (IAM's own reads seeing what it just created) rather than
    # an unconditional pause.
    def _both_visible():
        try:
            iam.get_role(RoleName=svc_role)
            iam.get_instance_profile(InstanceProfileName=ec2_role)
            return True
        except Exception as exc:  # noqa: BLE001
            if "NoSuchEntity" in str(exc):
                return False
            raise
    _poll_until(
        _both_visible, lambda ok: ok, timeout_s=60, interval_s=2.0,
        description="IAM role and instance profile becoming visible after creation",
    )
    return svc_role, ec2_role


def _empty_and_delete_bucket(s3, bucket):
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _stage_job_bucket(ctx):
    """Create a bucket holding the PySpark script, and register empty-then-delete teardown."""
    s3 = ctx.client("s3")
    bucket = _unique_name("emr-dp-")
    kwargs = {"Bucket": bucket}
    # Not a region assumption: S3's CreateBucket rejects an explicit LocationConstraint for
    # us-east-1 specifically (its bucket API predates the parameter), so this branches on an S3
    # API quirk, not on where the check happens to run.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    # Registered before the cluster, so LIFO empties the bucket AFTER the cluster is terminated —
    # the job's own output objects are included in the sweep.
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_object(Bucket=bucket, Key=_JOB_KEY, Body=_SPARK_JOB.encode())
    return s3, bucket


def _spark_output(s3, bucket):
    """Return (keys, payload) for the job's S3 output, or (keys, None) if no part file is there."""
    keys = sorted(
        o["Key"]
        for page in s3.get_paginator("list_objects_v2").paginate(
            Bucket=bucket, Prefix=f"{_OUT_PREFIX}/")
        for o in page.get("Contents", [])
    )
    parts = [k for k in keys if "/part-" in k]
    if not parts:
        return keys, None
    body = s3.get_object(Bucket=bucket, Key=parts[0])["Body"].read().decode().strip()
    return keys, body


_CLUSTER_GONE_CODES = ("InvalidRequestException", "ClusterNotFound",
                       "ResourceNotFoundException", "EntityNotFoundException")


def _cluster_is_gone(exc):
    """True only for the error that means the cluster no longer exists.

    EMR has no ClusterNotFound code: describing an unknown or reaped cluster comes back as
    InvalidRequestException ("Cluster id 'j-...' is not valid"). Everything else — throttling, a
    socket timeout, a brief 5xx — must NOT be read as termination. Over a wait that can run 900s on
    real AWS a transient error is far likelier than a genuine disappearance, and treating one as
    "gone" would abort the wait and hand the IAM deletions a cluster that is still assuming the
    service role: exactly the stranded-instance race the wait exists to close.
    """
    code = getattr(exc, "response", None) or {}
    code = code.get("Error", {}).get("Code", "")
    return code in _CLUSTER_GONE_CODES or "is not valid" in str(exc) or "does not exist" in str(exc)


def _terminate_and_await_teardown(ctx, emr, cluster_id):
    """Terminate the cluster and WAIT for the termination to finish.

    TerminateJobFlows returns immediately while EMR spends minutes winding the cluster down, and it
    needs the service role for that entire window. Cleanups run LIFO with the IAM deletions
    registered BEFORE the cluster (the roles have to exist first), so a bare terminate would let
    delete_role run while EMR is still using it — stranding the EC2 instances behind a cluster EMR
    can no longer tear down, a cost leak no assertion in the check would notice. Bounded: a
    cluster still not terminated at the deadline raises, so the leak reaches cleanup_detail.
    """
    emr.terminate_job_flows(JobFlowIds=[cluster_id])
    deadline = min(time.monotonic() + 900, _cleanup_deadline(ctx))
    while time.monotonic() < deadline:
        try:
            state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        except Exception as exc:  # noqa: BLE001
            if _cluster_is_gone(exc):
                return
            # Transient: keep waiting. Bailing out here would let delete_role run against a live
            # cluster, which is the whole failure mode this helper was added to prevent.
            time.sleep(15)
            continue
        if state in ("TERMINATED", "TERMINATED_WITH_ERRORS"):
            return
        time.sleep(15)
    raise AssertionError(f"EMR cluster {cluster_id} did not reach TERMINATED within 900s of TerminateJobFlows")


def _delete_with_retry(fn, attempts=6, delay=10):
    """Run an IAM delete, retrying DeleteConflict.

    Even once the cluster reports TERMINATED, IAM can briefly still see the instance profile as in
    use for a short while.
    """
    for i in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001
            if "DeleteConflict" not in str(exc) or i == attempts - 1:
                raise
            time.sleep(delay)


def _run_basic_cluster(emr, ctx, service_role, job_flow_role, name=None, track=True, **overrides):
    name = name or _unique_name("emr-cluster-")
    params = dict(
        Name=name,
        ReleaseLabel=RELEASE_LABEL,
        Instances={
            "InstanceCount": 1,
            "MasterInstanceType": INSTANCE_TYPE,
            "SlaveInstanceType": INSTANCE_TYPE,
            "KeepJobFlowAliveWhenNoSteps": True,
            "TerminationProtected": False,
        },
        ServiceRole=service_role,
        JobFlowRole=job_flow_role,
        VisibleToAllUsers=True,
        Applications=[{"Name": "Hadoop"}],
        Tags=MANAGED_TAGS,
    )
    params.update(overrides)
    left = ctx.time_left()
    deadline = time.monotonic() + (320 if left is None else min(320, left))
    while True:
        try:
            resp = emr.run_job_flow(**params)
            break
        except ClientError as exc:
            lowered = str(exc).lower()
            # IAM has not yet propagated the new instance profile to EMR.
            propagating = "invalid instanceprofile" in lowered or "invalid ec2" in lowered
            if not propagating or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    cluster_id = resp["JobFlowId"]
    if track:
        ctx.on_cleanup(
            lambda: _terminate_and_await_teardown(ctx, emr, cluster_id))
    return cluster_id

CHECK = "emr-run-step-spark"
GROUP = 'data-plane'
SERVICES = ['emr']


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Spark step writes the sum of squares 1..100 (338350) and a _SUCCESS marker to S3; the cluster then
    self-terminates with ALL_STEPS_COMPLETED, leaves the live listing, and AddJobFlowSteps on it fails
    with ValidationException, HTTP 400 and AWS's exact message."""
    emr = ctx.client("emr")

    service_role, job_flow_role = _ensure_emr_roles(ctx)
    s3, bucket = _stage_job_bucket(ctx)
    out_uri = f"s3://{bucket}/{_OUT_PREFIX}"

    step = {
        "Name": "sim2real-spark-sum-squares",
        "ActionOnFailure": "CONTINUE",
        "HadoopJarStep": {
            "Jar": "command-runner.jar",
            "Args": [
                "spark-submit",
                "--deploy-mode",
                "client",
                f"s3://{bucket}/{_JOB_KEY}",
                str(_JOB_N),
                out_uri,
            ],
        },
    }

    cluster_id = _run_basic_cluster(
        emr, ctx, service_role, job_flow_role,
        Applications=[{"Name": "Spark"}],
        Instances={
            "InstanceCount": 1,
            "MasterInstanceType": INSTANCE_TYPE,
            "KeepJobFlowAliveWhenNoSteps": False,
            "TerminationProtected": False,
            "Ec2SubnetId": _private_network(ctx, INSTANCE_TYPE)[1],
        },
        Steps=[step],
    )

    # Resolve the step id (ListSteps returns newest-first).
    steps = emr.list_steps(ClusterId=cluster_id).get("Steps", [])
    assert steps, f"no steps found on cluster {cluster_id}"
    step_id = steps[0]["Id"]

    # Every target gets the suite budget for each wait.
    ready_budget = _SUITE_BUDGET_S
    step_budget = _SUITE_BUDGET_S
    poll_interval = 30

    # Phase 1: the cluster must actually boot Hadoop/Spark and reach RUNNING/WAITING (or
    # self-terminate cleanly after running our step — KeepJobFlowAliveWhenNoSteps is False).
    # Terminal-failed cluster states are dead ends — break out immediately instead of waiting
    # out the whole budget. An emulator that accepts RunJobFlow but never lands the cluster
    # in a running/terminal-clean state has already lost: no Spark will ever run.
    def cluster_state() -> str:
        return emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]

    _CLUSTER_READY = {"RUNNING", "WAITING", "TERMINATED"}
    _CLUSTER_BAD = {"TERMINATED_WITH_ERRORS", "INTERNAL_ERROR"}
    try:
        cstate = _poll_until(
            cluster_state,
            lambda s: s in _CLUSTER_READY or s in _CLUSTER_BAD,
            timeout_s=ready_budget,
            interval_s=poll_interval,
            description=f"EMR cluster {cluster_id} reaching RUNNING/WAITING",
        )
    except AssertionError as exc:
        _dp_fail(
            f"EMR cluster {cluster_id} never reached RUNNING/WAITING within {ready_budget}s: "
            f"emulator accepted RunJobFlow but never booted a real Hadoop/Spark cluster ({exc})"
        )
    if cstate in _CLUSTER_BAD:
        msg = f"EMR cluster {cluster_id} reached terminal-failed state {cstate!r}"
        _dp_fail(f"{msg}: emulator accepted RunJobFlow but the cluster never came up")

    # Phase 2: the STEP itself must reach COMPLETED — proof the backend actually ran Spark.
    # Break early on any terminal state (success OR failure) rather than polling to the budget.
    def step_state() -> str:
        return emr.describe_step(ClusterId=cluster_id, StepId=step_id)["Step"][
            "Status"
        ]["State"]

    _STEP_TERMINAL = {
        "COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED",
        "TERMINATED_WITH_ERRORS", "INTERNAL_ERROR",
    }
    try:
        final = _poll_until(
            step_state,
            lambda s: s in _STEP_TERMINAL,
            timeout_s=step_budget,
            interval_s=poll_interval,
            description=f"Spark step {step_id} on cluster {cluster_id} reaching a terminal state",
        )
    except AssertionError as exc:
        _dp_fail(
            f"Spark step {step_id} on cluster {cluster_id} never reached a terminal state "
            f"within {step_budget}s: emulator accepted the EMR control-plane calls but never "
            f"actually ran the Spark step ({exc})"
        )
    if final != "COMPLETED":
        msg = f"Spark step {step_id} ended in {final!r}, expected COMPLETED"
        # Emulator took the RunJobFlow / step submission but the native Spark job never ran to
        # success.
        _dp_fail(
            f"{msg}: emulator accepted the EMR control-plane calls but never actually ran "
            "the Spark step to success"
        )

    # Phase 3: the actual data plane. COMPLETED is a string the backend picked; the job's output
    # object is not. Spark writes it before the step reports terminal, so this is a short poll
    # against read-after-write lag, not a second wait for the job.
    try:
        keys, payload = _poll_until(
            lambda: _spark_output(s3, bucket),
            lambda kp: kp[1] is not None,
            timeout_s=120,
            interval_s=5,
            description=f"Spark job output under s3://{bucket}/{_OUT_PREFIX}/",
        )
    except AssertionError as exc:
        msg = (
            f"Spark step {step_id} reported COMPLETED but wrote no output part file to "
            f"s3://{bucket}/{_OUT_PREFIX}/ ({exc})"
        )
        _dp_fail(f"{msg}: the COMPLETED status was fabricated — no Spark job actually ran")

    if not any(k.endswith("/_SUCCESS") for k in keys):
        msg = (
            f"Spark job output under s3://{bucket}/{_OUT_PREFIX}/ has no _SUCCESS marker "
            f"(keys={keys}): the write did not complete"
        )
        _dp_fail(msg)

    expected = f"{_JOB_N},{_JOB_EXPECTED}"
    if payload != expected:
        msg = (
            f"Spark job computed {payload!r}, expected {expected!r} "
            f"(sum of squares 1..{_JOB_N} over 4 partitions)"
        )
        _dp_fail(f"{msg}: the backend ran something, but not Spark semantics")

    # The cluster self-terminates once its only step is done (KeepJobFlowAliveWhenNoSteps is
    # False): poll to that terminal state, then prove it unlisted among live clusters and unusable.
    status = _poll_until(
        lambda: emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"],
        lambda st: st["State"] in ("TERMINATED", "TERMINATED_WITH_ERRORS"),
        timeout_s=_SUITE_BUDGET_S,
        interval_s=poll_interval,
        description=f"EMR cluster {cluster_id} self-terminating after its last step",
    )
    assert status["State"] == "TERMINATED", f"cluster {cluster_id} ended {status!r}, expected TERMINATED"
    reason = (status.get("StateChangeReason") or {}).get("Code")
    assert reason == "ALL_STEPS_COMPLETED", (
        f"cluster {cluster_id} terminated with reason {reason!r}, expected ALL_STEPS_COMPLETED"
    )
    live = [
        c["Id"]
        for page in emr.get_paginator("list_clusters").paginate(
            ClusterStates=["STARTING", "BOOTSTRAPPING", "RUNNING", "WAITING"]
        )
        for c in page["Clusters"]
    ]
    assert cluster_id not in live, f"terminated cluster {cluster_id} is still listed among live clusters"
    try:
        emr.add_job_flow_steps(JobFlowId=cluster_id, Steps=[step])
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        http = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        message = exc.response.get("Error", {}).get("Message") or ""
    else:
        raise AssertionError(f"AddJobFlowSteps on the terminated cluster {cluster_id} was ACCEPTED")
    assert code == "ValidationException", f"expected ValidationException adding a step to a terminated cluster, got {code}"
    assert http == 400, f"expected HTTP 400 adding a step to a terminated cluster, got {http}"
    expected_message = "A job flow that is shutting down, terminated, or finished may not be modified."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"


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
