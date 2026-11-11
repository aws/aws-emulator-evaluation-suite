"""scaling-managed-scaling-headroom-adds-real-instances-for-pending-yarn-work."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "scaling-managed-scaling-headroom-adds-real-instances-for-pending-yarn-work"
GROUP = "data-plane"
SERVICES = ["emr"]

_SCENARIO = "emr-managed-scaling-headroom"
_PREFIX = "sim2real-behav-emrms-"

# Creates its own VPC/subnet/IGW/route: an account need not have a default VPC.

INSTANCE_TYPE = "m5.xlarge"
# Pinned to 6.x: from emr-7.10.0 S3A replaces EMRFS as the default s3:// connector, which changes
# the committer that writes the output this check reads back.
RELEASE_LABEL = "emr-6.15.0"

# One primary node (EMR never scales it after the initial configuration),
# plus one core and one task node so a task instance group exists for managed scaling to grow.
_CORE_COUNT = 1
_TASK_COUNT = 1
_BASELINE_UNITS = _CORE_COUNT + _TASK_COUNT
# The clamp: no headroom at all above what is already provisioned.
_CLAMPED_MAX = _BASELINE_UNITS
# The headroom, applied later on the very same cluster. The only variable that changes.
_OPEN_MAX = 5
# How long the clamped ceiling is watched under the pending demand, from the step's submission.
_CLAMP_WINDOW_S = 180
# MinimumCapacityUnits cannot equal the clamped maximum: RunJobFlow rejects min == max, so a clamped
# policy can always scale IN and the absence arm bounds the requested TOTAL, not a fleet held still.
_MIN_UNITS = 1

# The workload. 320 partitions x 20s of in-partition CPU burn is ~6400 task-seconds, which at the
# ~12 concurrent tasks two nodes can host is ~9 minutes of runtime — long enough that the pending
# queue is still deep when the ceiling is raised.
_N_PARTS = 320
_BUSY_S = 20.0
_REQUESTED_EXECUTORS = 20
_EXECUTOR_MEMORY = "3G"
_EXECUTOR_CORES = 2

_JOB_KEY = "job/scale_job.py"
_OUT_PREFIX = "out/scaling"

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
        "Effect": "Allow",
        "Principal": {"Service": "ec2.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
# AmazonElasticMapReduceRole, NOT AmazonEMRServicePolicy_v2: v2 only grants access to network
# resources tagged `for-use-with-amazon-emr-managed-policies`.
#
# It is also what a managed scaling activity acts through: managed scaling needs no separate
# AutoScalingRole (that parameter exists for custom auto scaling policies only), so the EC2
# RunInstances/TerminateInstances this check observes come from this role.
_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
# Grants the cluster's EC2 instances the S3 access that makes the data plane below reachable at all.
_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"

_CLUSTER_GONE_CODES = (
    "InvalidRequestException", "ClusterNotFound", "ResourceNotFoundException",
    "EntityNotFoundException",
)
TERMINAL_STEP_STATES = {"COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"}
TERMINAL_CLUSTER_STATES = {"TERMINATED", "TERMINATED_WITH_ERRORS"}
BAD_CLUSTER_STATES = {"TERMINATED_WITH_ERRORS", "INTERNAL_ERROR"}
LIVE_INSTANCE_STATES = ["AWAITING_FULFILLMENT", "PROVISIONING", "BOOTSTRAPPING", "RUNNING"]

# The Spark application. Deliberately NOT an f-string: every parameter arrives on argv, so no brace
# in this program can be eaten by interpolation. It burns CPU inside each partition so that YARN
# keeps real work queued, then writes the aggregate back through EMRFS with saveAsTextFile.
_SPARK_JOB = '''import socket
import sys
import time

from pyspark.sql import SparkSession

out_uri = sys.argv[1]
n_parts = int(sys.argv[2])
busy_s = float(sys.argv[3])


def work(values):
    total = 0
    for value in values:
        total += value
    deadline = time.time() + busy_s
    spins = 0
    while time.time() < deadline:
        spins += 1
    yield (total, socket.gethostname(), spins)


spark = SparkSession.builder.appName("sim2real-managed-scaling").getOrCreate()
sc = spark.sparkContext
rows = sc.parallelize(range(1, n_parts * 100 + 1), n_parts).mapPartitions(work).collect()
total = sum(row[0] for row in rows)
hosts = sorted({row[1] for row in rows})
expected = (n_parts * 100) * (n_parts * 100 + 1) // 2
sc.parallelize(
    ["%d %d %d %d" % (total, expected, len(rows), len(hosts))], 1
).saveAsTextFile(out_uri)
spark.stop()
'''


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
    """Create the EMR service role and the EC2 instance profile; returns (service, ec2) names.

    Created in-check: EMR_DefaultRole / EMR_EC2_DefaultRole need not exist in the account.
    """
    iam = ctx.client("iam")
    svc_role = ctx.unique_name(_PREFIX + "svc-")
    ec2_role = ctx.unique_name(_PREFIX + "ec2-")

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

    # IAM eventual consistency: wait (bounded) for the instance profile to be readable; RunJobFlow's
    # transient retry in _run_cluster is the backstop.
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            iam.get_instance_profile(InstanceProfileName=ec2_role)
            break
        except Exception:  # noqa: BLE001 — prerequisite polling only, never an assertion
            time.sleep(2)
    return svc_role, ec2_role


def _pick_subnet(ctx, run_state: dict):
    """This check's private subnet (see _private_network)."""
    return _private_network(ctx, run_state, INSTANCE_TYPE)[1]


def _make_bucket(ctx, s3):
    """Create the scratch/log bucket, registered BEFORE the cluster so LIFO empties it AFTER."""
    bucket = ctx.unique_name(_PREFIX)

    def _cleanup():
        def _purge_and_delete():
            for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
                victims = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                           for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
                if victims:
                    failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": victims}).get("Errors")
                    if failed:
                        raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            s3.delete_bucket(Bucket=bucket)

        from botocore.exceptions import ClientError

        try:
            _purge_and_delete()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _TAGS})
    return bucket


def _cluster_is_gone(exc):
    """True only for the error that means the cluster no longer exists.

    EMR has no ClusterNotFound code: describing a reaped cluster comes back as
    InvalidRequestException ("Cluster id 'j-...' is not valid"). A throttle or a brief 5xx must NOT
    be read as termination — treating one as "gone" hands the IAM deletions a cluster that is still
    assuming the service role.
    """
    code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
    return code in _CLUSTER_GONE_CODES or "is not valid" in str(exc)


def _terminate_and_await_teardown(ctx, run_state: dict, emr, cluster_id):
    """Terminate and WAIT: EMR needs the service role for the whole wind-down, and cleanups run
    LIFO with the IAM deletions registered first, so a bare terminate strands the EC2 fleet —
    including any instance a managed scaling activity added."""
    from botocore.exceptions import ClientError

    for fn in (lambda: emr.set_termination_protection(JobFlowIds=[cluster_id], TerminationProtected=False),
               lambda: emr.terminate_job_flows(JobFlowIds=[cluster_id])):
        try:
            fn()
        except ClientError as exc:
            if _cluster_is_gone(exc):
                return
            # Only a cluster that has already terminated may refuse these calls.
            if emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"] not in TERMINAL_CLUSTER_STATES:
                raise
    deadline = min(time.monotonic() + 900, _cleanup_deadline(ctx, run_state))
    while time.monotonic() < deadline:
        try:
            state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        except ClientError as exc:
            if _cluster_is_gone(exc):
                return
            raise
        if state in TERMINAL_CLUSTER_STATES:
            return
        time.sleep(2)
    raise RuntimeError(f"EMR cluster {cluster_id} did not terminate within the teardown wait")


def _run_cluster(emr, ctx, run_state: dict, service_role, job_flow_role, **params):
    """RunJobFlow, retrying only transient IAM-propagation / throttle errors, registering the
    terminate-and-wait teardown immediately after the id exists."""
    left = ctx.time_left()
    deadline = time.monotonic() + (320 if left is None else min(320, max(0.0, left - 5)))
    while True:
        try:
            resp = emr.run_job_flow(ServiceRole=service_role, JobFlowRole=job_flow_role, **params)
            break
        except Exception as exc:  # noqa: BLE001 — classified below, re-raised if fatal
            low = str(exc).lower()
            transient = ("throttl" in low or "rate exceeded" in low
                         or "invalid instanceprofile" in low or "invalid ec2" in low
                         or "failed to authorize instance profile" in low)
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    cluster_id = resp["JobFlowId"]
    ctx.on_cleanup(lambda: _terminate_and_await_teardown(ctx, run_state, emr, cluster_id))
    return cluster_id


def _instances(subnet):
    """One primary, one core and one task group. KeepJobFlowAliveWhenNoSteps=True so the only thing
    that can end the cluster is the teardown: an ALL_STEPS_COMPLETED auto-shutdown would race the
    S3 reads and the ListInstances sampling the assertions depend on."""
    return {
        "InstanceGroups": [
            {"Name": "sim2real-primary", "InstanceRole": "MASTER",
             "InstanceType": INSTANCE_TYPE, "InstanceCount": 1, "Market": "ON_DEMAND"},
            {"Name": "sim2real-core", "InstanceRole": "CORE",
             "InstanceType": INSTANCE_TYPE, "InstanceCount": _CORE_COUNT, "Market": "ON_DEMAND"},
            {"Name": "sim2real-task", "InstanceRole": "TASK",
             "InstanceType": INSTANCE_TYPE, "InstanceCount": _TASK_COUNT, "Market": "ON_DEMAND"},
        ],
        "KeepJobFlowAliveWhenNoSteps": True,
        "TerminationProtected": False,
        "Ec2SubnetId": subnet,
    }


def _shell_step(name, script, on_failure="CONTINUE"):
    """A step that runs `script` through the cluster's own shell via command-runner.jar."""
    return {
        "Name": name,
        "ActionOnFailure": on_failure,
        "HadoopJarStep": {"Jar": "command-runner.jar", "Args": ["bash", "-c", script]},
    }


def _limits(maximum):
    """A managed scaling policy over instance-group units with `maximum` as the ceiling."""
    return {
        "ComputeLimits": {
            "UnitType": "Instances",
            "MinimumCapacityUnits": _MIN_UNITS,
            "MaximumCapacityUnits": maximum,
        }
    }


def _live_non_primary(emr, cluster_id):
    """Every live CORE/TASK instance on the cluster, as {Ec2InstanceId: state}.

    Paginated: a truncated page would understate the measured capacity.
    """
    out = {}
    for page in emr.get_paginator("list_instances").paginate(
        ClusterId=cluster_id,
        InstanceGroupTypes=["CORE", "TASK"],
        InstanceStates=LIVE_INSTANCE_STATES,
    ):
        for inst in page["Instances"]:
            out[inst["Ec2InstanceId"]] = inst["Status"]["State"]
    return out


def _requested_non_primary(emr, cluster_id):
    """The CORE/TASK groups' RequestedInstanceCount, as {InstanceGroupType: count}.

    ComputeLimits bounds this; a live count can sit above the ceiling while a node decommissions.
    """
    return {
        g["InstanceGroupType"]: g["RequestedInstanceCount"]
        for page in emr.get_paginator("list_instance_groups").paginate(ClusterId=cluster_id)
        for g in page["InstanceGroups"]
        if g["InstanceGroupType"] in ("CORE", "TASK")
    }


def _await_step(emr, cluster_id, step_id, *, timeout_s, description):
    """Wait for one step to reach a TERMINAL state and return the described step."""
    return _poll(
        lambda: emr.describe_step(ClusterId=cluster_id, StepId=step_id)["Step"],
        lambda s: s["Status"]["State"] in TERMINAL_STEP_STATES,
        timeout_s=timeout_s,
        interval_s=2,
        description=description,
    )


def _keys_under(s3, bucket, prefix):
    """Every key under a prefix."""
    return sorted(
        o["Key"]
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix)
        for o in page.get("Contents", [])
    )


def _get_text(s3, bucket, key):
    """Read an object as text. No try/except: a missing key must fail loudly, not degrade."""
    return s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode("utf-8").strip()



@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Managed scaling under a ceiling equal to provisioned capacity never targets more core+task
    capacity, but raising the ceiling adds real EC2 instances for pending YARN demand, and the Spark
    job still completes with the correct sum in S3.

    Reference: https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-managed-scaling.html
    """
    # Per-run state: the teardown deadline, the private network and the clusters placed in it.
    run_state: dict = {}
    emr = ctx.client("emr")
    s3 = ctx.client("s3")
    ec2 = ctx.client("ec2")

    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account, "STS must report the account id before any cluster is launched"

    bucket = _make_bucket(ctx, s3)
    service_role, job_flow_role = _ensure_emr_roles(ctx)
    subnet = _pick_subnet(ctx, run_state)
    region = ctx.region

    s3.put_object(Bucket=bucket, Key=_JOB_KEY, Body=_SPARK_JOB.encode("utf-8"))

    step_script = (
        f"set -eu; "
        f"aws s3 cp s3://{bucket}/{_JOB_KEY} /tmp/scale_job.py --region {region}; "
        f"spark-submit --master yarn --deploy-mode client "
        f"--conf spark.dynamicAllocation.enabled=false "
        f"--conf spark.scheduler.minRegisteredResourcesRatio=0.0 "
        f"--num-executors {_REQUESTED_EXECUTORS} --executor-cores {_EXECUTOR_CORES} "
        f"--executor-memory {_EXECUTOR_MEMORY} "
        f"/tmp/scale_job.py s3://{bucket}/{_OUT_PREFIX} {_N_PARTS} {_BUSY_S}"
    )
    step_name = "sim2real-scaling-demand"

    cluster_id = _run_cluster(
        emr, ctx, run_state, service_role, job_flow_role,
        Name=ctx.unique_name(_PREFIX),
        ReleaseLabel=RELEASE_LABEL,
        LogUri=f"s3://{bucket}/logs/",
        Applications=[{"Name": "Hadoop"}, {"Name": "Spark"}],
        Instances=_instances(subnet),
        ManagedScalingPolicy=_limits(_CLAMPED_MAX),
        StepConcurrencyLevel=1,
        VisibleToAllUsers=True,
        Tags=_TAGS,
    )

    # --- the cluster comes up with exactly the capacity we asked for, and the clamped ceiling.
    state = _poll(
        lambda: emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"],
        lambda s: s == "WAITING" or s in BAD_CLUSTER_STATES,
        timeout_s=1200, interval_s=2,
        description=f"cluster {cluster_id} reaches WAITING",
    )
    assert state == "WAITING", (
        f"the cluster must reach WAITING before any scaling claim can be made; it reached {state!r}"
    )

    clamped = emr.get_managed_scaling_policy(ClusterId=cluster_id)["ManagedScalingPolicy"]
    assert clamped["ComputeLimits"]["MaximumCapacityUnits"] == _CLAMPED_MAX, (
        f"the cluster must be running under the clamped ceiling before the workload starts: "
        f"expected MaximumCapacityUnits={_CLAMPED_MAX}, got {clamped['ComputeLimits']!r}"
    )

    baseline = _live_non_primary(emr, cluster_id)
    assert len(baseline) == _BASELINE_UNITS, (
        f"the cluster must start with exactly the {_BASELINE_UNITS} non-primary instances requested "
        f"({_CORE_COUNT} core + {_TASK_COUNT} task) before any scaling activity; ListInstances "
        f"reported {len(baseline)}: {baseline!r}"
    )
    baseline_requested = _requested_non_primary(emr, cluster_id)
    assert sum(baseline_requested.values()) == _BASELINE_UNITS, (
        f"the CORE and TASK groups must request exactly {_BASELINE_UNITS} instances between them "
        f"before any scaling activity; ListInstanceGroups reported {baseline_requested!r}"
    )

    submitted = emr.add_job_flow_steps(
        JobFlowId=cluster_id, Steps=[_shell_step(step_name, step_script)]
    )["StepIds"]
    assert len(submitted) == 1, f"AddJobFlowSteps must mint exactly one step id, got {submitted!r}"
    step_id = submitted[0]

    # --- ABSENCE ARM: the ceiling holds while the pending queue is deep. Asserted over REQUESTED
    # capacity, which is what ComputeLimits bounds; a live count above the ceiling during a
    # decommission is legal.
    peak_clamped = 0
    clamp_samples = []
    live_samples = []
    clamp_deadline = time.monotonic() + _CLAMP_WINDOW_S
    while time.monotonic() < clamp_deadline:
        requested = sum(_requested_non_primary(emr, cluster_id).values())
        peak_clamped = max(peak_clamped, requested)
        clamp_samples.append(requested)
        live_samples.append(len(_live_non_primary(emr, cluster_id)))
        time.sleep(2)
    assert len(clamp_samples) >= 2, (
        f"the clamp window must have produced at least two ListInstanceGroups samples, got "
        f"{clamp_samples!r}"
    )
    assert peak_clamped <= _CLAMPED_MAX, (
        f"managed scaling must not TARGET capacity beyond MaximumCapacityUnits={_CLAMPED_MAX} "
        f"however deep the pending YARN queue is; the requested core+task count reached "
        f"{peak_clamped} (requested samples {clamp_samples!r}, live samples {live_samples!r})"
    )

    step_mid = emr.describe_step(ClusterId=cluster_id, StepId=step_id)["Step"]["Status"]["State"]
    assert step_mid in ("PENDING", "RUNNING"), (
        f"the demand step must still be pending or running when the ceiling is raised — both arms "
        f"only mean anything while YARN still has unsatisfied container requests. It was "
        f"{step_mid!r} after the {_CLAMP_WINDOW_S}s clamp window, so the workload was mis-sized for "
        f"this cluster"
    )

    # --- break exactly one thing: raise the ceiling. Nothing else changes.
    emr.put_managed_scaling_policy(ClusterId=cluster_id, ManagedScalingPolicy=_limits(_OPEN_MAX))
    opened = emr.get_managed_scaling_policy(ClusterId=cluster_id)["ManagedScalingPolicy"]
    assert opened["ComputeLimits"]["MaximumCapacityUnits"] == _OPEN_MAX, (
        f"PutManagedScalingPolicy must have raised the ceiling to {_OPEN_MAX}; "
        f"GetManagedScalingPolicy reports {opened['ComputeLimits']!r}"
    )

    # --- EFFECT ARM: capacity grows, and the step finishes. One loop, so a scale-out that lands
    # just as the application ends is still observed. The deadline is patience, not an assertion.
    peak_open = len(baseline)
    peak_ids = set(baseline)
    peak_open_requested = 0
    step = None
    terminal_at = None
    open_deadline = time.monotonic() + 900
    while time.monotonic() < open_deadline:
        live = _live_non_primary(emr, cluster_id)
        if len(live) > peak_open:
            peak_open, peak_ids = len(live), set(live)
        peak_open_requested = max(
            peak_open_requested, sum(_requested_non_primary(emr, cluster_id).values())
        )
        described = emr.describe_step(ClusterId=cluster_id, StepId=step_id)["Step"]
        if described["Status"]["State"] in TERMINAL_STEP_STATES:
            step = described
            terminal_at = terminal_at or time.monotonic()
            # Keep sampling for a short grace period after the step ends: a scale-out requested in
            # the application's last seconds can still appear in ListInstances. Bounded, because once
            # the queue has drained managed scaling scales IN, so a count that has not risen by now
            # never will — and a bounded grace turns "no scaling happened" into a clean assertion
            # failure instead of a wrapper timeout.
            grace_over = time.monotonic() - terminal_at >= 120
            if (peak_open_requested > _CLAMPED_MAX and peak_open > _CLAMPED_MAX) or grace_over:
                break
        time.sleep(2)
    assert step is not None, (
        f"step {step_id} on {cluster_id} did not reach a terminal state within 900s of the ceiling "
        f"being raised; peak live core+task count observed was {peak_open}"
    )
    assert peak_open_requested > _CLAMPED_MAX, (
        f"THE assertion: with MaximumCapacityUnits raised from {_CLAMPED_MAX} to {_OPEN_MAX} and "
        f"the same pending YARN demand, managed scaling must TARGET more core/task capacity than the "
        f"clamped ceiling allowed — a target it provably could not hold while the clamp was in force. "
        f"The requested core+task count never rose above {_CLAMPED_MAX} (peak "
        f"{peak_open_requested}, groups {_requested_non_primary(emr, cluster_id)!r})"
    )
    assert peak_open > _CLAMPED_MAX, (
        f"and the raised target must have become real machines: ListInstances must report more than "
        f"{_CLAMPED_MAX} live core+task instances, the count the clamped ceiling capped. It peaked at "
        f"{peak_open} (ids {sorted(peak_ids)!r}, baseline {sorted(baseline)!r})"
    )
    assert peak_open_requested <= _OPEN_MAX, (
        f"the raised ceiling is still a ceiling: the requested core+task count reached "
        f"{peak_open_requested}, above MaximumCapacityUnits={_OPEN_MAX}"
    )

    # --- the instances managed scaling added are real EC2 instances, not a control-plane fiction.
    added = sorted(set(peak_ids) - set(baseline))
    assert added, (
        f"the peak capacity {peak_open} must be made of instance ids the baseline did not contain; "
        f"peak ids {sorted(peak_ids)!r} vs baseline {sorted(baseline)!r}"
    )
    described_ec2 = {
        i["InstanceId"]: (i["InstanceType"], i["State"]["Name"])
        for page in ec2.get_paginator("describe_instances").paginate(InstanceIds=added)
        for r in page["Reservations"] for i in r["Instances"]
    }
    assert sorted(described_ec2) == added, (
        f"every instance managed scaling added must exist in EC2: asked about {added!r}, "
        f"describe_instances returned {sorted(described_ec2)!r}"
    )
    # The state is NOT asserted: managed scaling may legitimately start scaling back in the moment
    # the pending queue drains, so an added instance can be shutting-down by the time this runs. The
    # instance TYPE is the stable fact, and it is the one a fabricated ListInstances cannot produce.
    assert all(t == INSTANCE_TYPE for t, _ in described_ec2.values()), (
        f"managed scaling must have provisioned {INSTANCE_TYPE} instances, matching the groups it "
        f"grew; describe_instances reported {described_ec2!r}"
    )

    # --- the job still COMPLETED, and its output is arithmetically correct.
    assert step["Status"]["State"] == "COMPLETED", (
        f"the Spark application must still complete across the scaling event; step {step_id} ended "
        f"{step['Status']['State']!r} (reason {step['Status'].get('StateChangeReason')!r}, "
        f"failure {step['Status'].get('FailureDetails')!r})"
    )

    out_keys = _keys_under(s3, bucket, _OUT_PREFIX + "/")
    success = f"{_OUT_PREFIX}/_SUCCESS"
    parts = [k for k in out_keys if k.startswith(f"{_OUT_PREFIX}/part-")]
    assert success in out_keys, (
        f"the EMRFS commit must leave a _SUCCESS marker under {_OUT_PREFIX}/; keys were "
        f"{out_keys!r}"
    )
    assert len(parts) == 1, (
        f"the single-partition write must land exactly one part file under {_OUT_PREFIX}/; "
        f"got {parts!r}"
    )

    fields = _get_text(s3, bucket, parts[0]).split()
    assert len(fields) == 4, (
        f"the job's output line must be `total expected partitions hosts`; got {fields!r}"
    )
    total, expected, partitions, hosts = (int(f) for f in fields)
    closed_form = (_N_PARTS * 100) * (_N_PARTS * 100 + 1) // 2
    assert expected == closed_form, (
        f"the job must have been handed the workload this check sized: its own closed form was "
        f"{expected}, this check computed {closed_form}"
    )
    assert total == closed_form, (
        f"the aggregate the scaled cluster computed must be exactly the closed-form sum of "
        f"1..{_N_PARTS * 100}: expected {closed_form}, the job wrote {total}"
    )
    assert partitions == _N_PARTS, (
        f"every one of the {_N_PARTS} partitions must have reported a result; the job saw "
        f"{partitions}"
    )
    assert len(baseline) <= hosts <= peak_open, (
        f"the job's tasks must have run on at least the baseline capacity and no more hosts than "
        f"the control plane ever reported: {hosts} distinct executor hosts against baseline "
        f"{len(baseline)} and peak {peak_open}"
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
