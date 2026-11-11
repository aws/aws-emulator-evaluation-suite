"""spark-terminate-cluster-action-rejected-at-step-concurrency-two."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "spark-terminate-cluster-action-rejected-at-step-concurrency-two"
GROUP = "data-plane"
SERVICES = ["emr"]

_SCENARIO = "emr-spark-terminate-action-concurrency"
_PREFIX = "sim2real-behav-emrta-"

_JOB_KEY = "job/bad_input.py"
_BAD_PREFIX = "bad"
_DIAG_PREFIX = "diag"
_OUT_PREFIX = "out"
_CONTROL_KEY = f"{_OUT_PREFIX}/control"
_JOB_OUT_PREFIX = f"{_OUT_PREFIX}/aggregate"

# Four CSV records, exactly one unparseable against the declared integer schema; the counts show
# WHY the Spark step failed, so they are asserted rather than a bare non-zero exit.
_BAD_CSV = "1,10\n2,20\noops,notanumber\n4,40\n"
_BAD_ROWS = 4
_BAD_UNPARSEABLE = 1

_SPARK_JOB = '''\
import json
import sys

from pyspark.sql import SparkSession

base, nonce = sys.argv[1:3]
spark = SparkSession.builder.appName("sim2real-emr-bad-input").getOrCreate()

frame = spark.read.schema("id INT, amount INT").csv(base + "/BAD_PREFIX/")
rows = frame.collect()
bad = [r for r in rows if r["id"] is None or r["amount"] is None]

# The driver's own account of what it saw, published BEFORE it raises, under a prefix that is NOT
# the job's output prefix. A step that fails by exiting non-zero under command-runner.jar publishes
# no FailureDetails at all, so without this the only observable reason would be the cluster's.
detail = {"nonce": nonce, "rows": len(rows), "bad": len(bad)}
spark.sparkContext.parallelize([json.dumps(detail, sort_keys=True)], 1) \\
    .saveAsTextFile(base + "/DIAG_PREFIX")

if bad:
    raise RuntimeError(
        "sim2real-badinput-" + nonce + ": " + str(len(bad)) + " of " + str(len(rows))
        + " records do not parse against the declared schema"
    )

# Unreachable against the fixture above. Only a backend that silently repaired the malformed record
# gets here, and it must not be allowed to COMPLETE for a reason the check did not intend: the
# aggregate below is the output whose ABSENCE the check asserts.
frame.groupBy().sum("amount").write.mode("overwrite").parquet(base + "/JOB_OUT_PREFIX")
raise RuntimeError("sim2real-badinput-" + nonce + ": the malformed record parsed cleanly")
'''.replace("BAD_PREFIX", _BAD_PREFIX).replace(
    "DIAG_PREFIX", _DIAG_PREFIX).replace("JOB_OUT_PREFIX", _JOB_OUT_PREFIX)


INSTANCE_TYPE = "m5.xlarge"
# Pinned to the 6.x line: from emr-7.10.0 S3A replaces EMRFS as the default s3:// connector
# (https://docs.aws.amazon.com/emr/latest/ReleaseGuide/emr-s3a-migrate.html).
RELEASE_LABEL = "emr-6.15.0"

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
# AmazonElasticMapReduceRole, not AmazonEMRServicePolicy_v2: v2 only grants access to network
# resources tagged `for-use-with-amazon-emr-managed-policies`.
_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
# Grants the cluster's EC2 instances the S3 access that makes the data plane below reachable at all.
_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"

_CLUSTER_GONE_CODES = (
    "InvalidRequestException", "ClusterNotFound", "ResourceNotFoundException",
    "EntityNotFoundException",
)
TERMINAL_STEP_STATES = {"COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"}
TERMINAL_CLUSTER_STATES = {"TERMINATED", "TERMINATED_WITH_ERRORS"}


def _gone(fn, *codes):
    """Run a teardown call; return quietly only on the given not-found codes, raise the rest."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in codes:
            raise


def _error_response(fn):
    """The full Error dict from fn(), or None if fn() did not raise a ClientError."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]
    return None


_POLL_S = 2.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(probe, predicate, *, timeout_s, interval_s, description, ctx):
    """Poll probe() until predicate(result); RAISE on timeout (never return the last value)."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_with_retry(fn, attempts=60, delay=2):
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

    EMR_DefaultRole / EMR_EC2_DefaultRole do not exist in a fresh account.
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

    # IAM eventual consistency: wait, bounded, until IAM reports the profile carrying its role.
    # RunJobFlow's own bounded retry covers the remaining propagation to EMR.
    deadline = time.monotonic() + 60
    while not iam.get_instance_profile(InstanceProfileName=ec2_role)["InstanceProfile"]["Roles"]:
        if time.monotonic() >= deadline:
            raise AssertionError(f"instance profile {ec2_role} did not list its role within 60s")
        time.sleep(_POLL_S)
    return svc_role, ec2_role


def _make_network(ctx):
    """This check's private subnet (see _private_network)."""
    return _private_network(ctx, INSTANCE_TYPE)[1]


def _make_bucket(ctx, s3):
    """Create the scratch/log bucket, registered BEFORE the cluster so LIFO empties it AFTER."""
    bucket = ctx.unique_name(_PREFIX)

    def _cleanup():
        def _purge_and_delete():
            for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
                victims = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                           for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
                if victims:
                    s3.delete_objects(Bucket=bucket, Delete={"Objects": victims})
            s3.delete_bucket(Bucket=bucket)

        try:
            _purge_and_delete()
        except Exception as exc:  # noqa: BLE001 — teardown; only the bucket's own not-found is done
            if "NoSuchBucket" not in str(exc):
                raise RuntimeError(f"bucket {bucket} was not deleted: {exc!r}") from exc

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

    EMR has no ClusterNotFound code: a reaped cluster describes as InvalidRequestException.
    Transients must not be read as termination while the cluster still assumes the service role.
    """
    code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
    return code in _CLUSTER_GONE_CODES or "is not valid" in str(exc)


def _terminate_and_await_teardown(ctx, emr, cluster_id):
    """Terminate and wait: EMR needs the service role for the whole wind-down, and the IAM
    deletions run after this in LIFO order."""
    _gone(lambda: emr.set_termination_protection(
        JobFlowIds=[cluster_id], TerminationProtected=False), "ValidationException", "InvalidRequestException")
    _gone(lambda: emr.terminate_job_flows(JobFlowIds=[cluster_id]), "InvalidRequestException")
    last = None
    deadline = min(time.monotonic() + 900, _cleanup_deadline(ctx))
    while time.monotonic() < deadline:
        try:
            state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        except Exception as exc:  # noqa: BLE001 — teardown classification only
            if _cluster_is_gone(exc):
                return
            last = exc
            time.sleep(_POLL_S)
            continue
        if state in TERMINAL_CLUSTER_STATES:
            return
        last = state
        time.sleep(_POLL_S)
    raise RuntimeError(f"EMR cluster {cluster_id} was not deleted: {last!r}")


def _run_cluster(emr, ctx, service_role, job_flow_role, **params):
    """RunJobFlow, retrying only transient IAM-propagation / throttle errors, registering the
    terminate-and-wait teardown immediately after the id exists."""
    last = None
    resp = None
    deadline = time.monotonic() + _budget_s(ctx, 300)
    while True:
        try:
            resp = emr.run_job_flow(ServiceRole=service_role, JobFlowRole=job_flow_role, **params)
            break
        except Exception as exc:  # noqa: BLE001 — classified below, re-raised if fatal
            low = str(exc).lower()
            transient = ("throttl" in low or "rate exceeded" in low
                         or "invalid instanceprofile" in low or "invalid ec2" in low)
            if not transient or time.monotonic() >= deadline:
                if transient and _budget_spent(ctx):
                    raise TimeoutError("RunJobFlow succeeding: the run budget ended first; not graded")
                raise
            last = exc
            time.sleep(_POLL_S)
    if resp is None:
        raise AssertionError(f"RunJobFlow never succeeded: {last}")
    cluster_id = resp["JobFlowId"]
    ctx.on_cleanup(lambda: _terminate_and_await_teardown(ctx, emr, cluster_id))
    return cluster_id


def _instances(subnet, keep_alive=True, core=0):
    """One primary, optionally `core` core nodes, with KeepJobFlowAliveWhenNoSteps=True so only the
    failing step's ActionOnFailure or teardown can end the cluster."""
    groups = [{
        "Name": "sim2real-primary", "InstanceRole": "MASTER",
        "InstanceType": INSTANCE_TYPE, "InstanceCount": 1, "Market": "ON_DEMAND",
    }]
    if core:
        groups.append({
            "Name": "sim2real-core", "InstanceRole": "CORE",
            "InstanceType": INSTANCE_TYPE, "InstanceCount": core, "Market": "ON_DEMAND",
        })
    return {
        "InstanceGroups": groups,
        "KeepJobFlowAliveWhenNoSteps": keep_alive,
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


def _await_step(ctx, emr, cluster_id, step_id, *, timeout_s, description):
    """Wait for one step to reach a TERMINAL state and return the described step."""
    return _poll(
        lambda: emr.describe_step(ClusterId=cluster_id, StepId=step_id)["Step"],
        lambda s: s["Status"]["State"] in TERMINAL_STEP_STATES,
        timeout_s=timeout_s,
        interval_s=_POLL_S,
        description=description,
        ctx=ctx,
    )


def _step_ids(emr, cluster_id):
    """Every step id currently on the cluster, newest first as EMR returns them."""
    return [s["Id"] for page in emr.get_paginator("list_steps").paginate(ClusterId=cluster_id)
            for s in page.get("Steps", [])]


def _get_text(s3, bucket, key):
    """Read an object as text. No try/except: a missing key must fail loudly, not degrade."""
    return s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode("utf-8").strip()


def _keys_under(s3, bucket, prefix):
    """Every key under a prefix."""
    return sorted(
        o["Key"]
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix)
        for o in page.get("Contents", [])
    )



@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """EMR rejects ActionOnFailure=TERMINATE_CLUSTER at StepConcurrencyLevel=2 and creates no step;
    the identical step is accepted at level 1, where the Spark job fails on bad input, ends the
    cluster with STEP_FAILURE and writes no output.

    Reference: https://docs.aws.amazon.com/emr/latest/APIReference/API_StepConfig.html
    Reference: https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-work-with-steps.html
    Reference: https://docs.aws.amazon.com/emr/latest/APIReference/API_ModifyCluster.html
    """
    emr = ctx.client("emr")
    s3 = ctx.client("s3")

    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account, "STS must report the caller's account id before any cluster is launched"

    bucket = _make_bucket(ctx, s3)
    service_role, job_flow_role = _ensure_emr_roles(ctx)
    subnet = _make_network(ctx)

    nonce = ctx.unique_name("ta-")
    s3.put_object(Bucket=bucket, Key=_JOB_KEY, Body=_SPARK_JOB.encode("utf-8"))
    s3.put_object(Bucket=bucket, Key=f"{_BAD_PREFIX}/records.csv", Body=_BAD_CSV.encode("utf-8"))
    base = f"s3://{bucket}"

    # Launched with NO steps, so the concurrency level is observable before anything is submitted.
    cluster_id = _run_cluster(
        emr, ctx, service_role, job_flow_role,
        Name=ctx.unique_name(_PREFIX),
        ReleaseLabel=RELEASE_LABEL,
        LogUri=f"s3://{bucket}/logs/",
        Applications=[{"Name": "Hadoop"}, {"Name": "Spark"}],
        Instances=_instances(subnet, keep_alive=True, core=1),
        StepConcurrencyLevel=2,
        VisibleToAllUsers=True,
        Tags=_TAGS,
    )

    def _cluster():
        return emr.describe_cluster(ClusterId=cluster_id)["Cluster"]

    state = _poll(
        lambda: _cluster()["Status"]["State"],
        lambda s: s not in ("STARTING", "BOOTSTRAPPING"),
        timeout_s=900, interval_s=_POLL_S, ctx=ctx,
        description=f"EMR cluster {cluster_id} finishing provisioning",
    )
    assert state == "WAITING", (
        f"a keep-alive cluster launched with no steps must settle in WAITING; got {state!r}"
    )
    assert _cluster().get("StepConcurrencyLevel") == 2, (
        f"the cluster must report the StepConcurrencyLevel it was launched with; got "
        f"{_cluster().get('StepConcurrencyLevel')!r}"
    )

    # Positive control: a CONTINUE step at level 2 writes real bytes to S3.
    control_id = emr.add_job_flow_steps(
        JobFlowId=cluster_id,
        Steps=[_shell_step(
            "sim2real-control",
            f"set -e; printf %s '{nonce}' > /tmp/control; "
            f"aws s3 cp /tmp/control s3://{bucket}/{_CONTROL_KEY} --region {ctx.region}",
        )],
    )["StepIds"][0]
    control = _await_step(
        ctx, emr, cluster_id, control_id, timeout_s=600,
        description=f"the control step {control_id} on {cluster_id} reaches a terminal state",
    )
    assert control["Status"]["State"] == "COMPLETED", (
        f"the control step must COMPLETE — without it the absent output below would say something "
        f"about the account rather than about EMR. Got {control['Status']['State']!r} "
        f"(reason {control['Status'].get('StateChangeReason')!r})"
    )
    assert _get_text(s3, bucket, _CONTROL_KEY) == nonce, (
        f"the control step must have written exactly its nonce to s3://{bucket}/{_CONTROL_KEY}"
    )
    assert _cluster().get("StepConcurrencyLevel") == 2, (
        "running a step must not change the cluster's StepConcurrencyLevel"
    )

    # One StepConfig object, submitted at level 2 now and again at level 1, so the requests are
    # identical.
    boom_step = {
        "Name": "sim2real-badinput-boom",
        "ActionOnFailure": "TERMINATE_CLUSTER",
        "HadoopJarStep": {
            "Jar": "command-runner.jar",
            "Args": ["spark-submit", "--deploy-mode", "client",
                     f"s3://{bucket}/{_JOB_KEY}", base, nonce],
        },
    }
    before_ids = _step_ids(emr, cluster_id)
    error = _error_response(
        lambda: emr.add_job_flow_steps(JobFlowId=cluster_id, Steps=[boom_step]))
    assert error is not None, (
        "AddJobFlowSteps carrying ActionOnFailure=TERMINATE_CLUSTER must be REJECTED while the "
        "cluster's StepConcurrencyLevel is 2; the call succeeded instead"
    )
    assert error["Code"] == "ValidationException", (
        f"the rejection must be a ValidationException, got {error!r}"
    )
    assert error["Message"] == "Action on failure 'TERMINATE_CLUSTER' is invalid.", (
        f"the message must name the failure action it refused, so the caller can tell this apart "
        f"from an unrelated validation error; got {error['Message']!r}"
    )
    after_ids = _step_ids(emr, cluster_id)
    assert after_ids == before_ids, (
        f"the rejection must be total — no step may be created by a refused AddJobFlowSteps. "
        f"Before: {before_ids!r}, after: {after_ids!r}"
    )

    # The same request, after the cluster state that forbade it is changed.
    modified = emr.modify_cluster(ClusterId=cluster_id, StepConcurrencyLevel=1)
    assert modified.get("StepConcurrencyLevel") == 1, (
        f"ModifyCluster must return the level it was asked to set, got {modified!r}"
    )
    assert _cluster().get("StepConcurrencyLevel") == 1, (
        f"the cluster must report the lowered level, got "
        f"{_cluster().get('StepConcurrencyLevel')!r}"
    )
    accepted = emr.add_job_flow_steps(JobFlowId=cluster_id, Steps=[boom_step])["StepIds"]
    assert len(accepted) == 1, (
        f"the byte-identical StepConfig that was just refused must now be accepted and return one "
        f"step id; got {accepted!r}"
    )
    boom_id = accepted[0]
    assert boom_id not in before_ids, (
        f"the accepted step must be a NEW step, not one of the pre-existing {before_ids!r}"
    )

    # The failure action now does what it says.
    boom = _await_step(
        ctx, emr, cluster_id, boom_id, timeout_s=900,
        description=f"the Spark step {boom_id} on {cluster_id} reaches a terminal state",
    )
    assert boom["Status"]["State"] == "FAILED", (
        f"the Spark step whose driver raises on the unparseable record must be FAILED; got "
        f"{boom['Status']['State']!r} (reason {boom['Status'].get('StateChangeReason')!r})"
    )

    diag_keys = _keys_under(s3, bucket, f"{_DIAG_PREFIX}/")
    diag_parts = [k for k in diag_keys if "/part-" in k]
    assert len(diag_parts) == 1, (
        f"the failing driver must have published exactly one diagnostic part file under "
        f"s3://{bucket}/{_DIAG_PREFIX}/; got {diag_keys!r}"
    )
    diag = json.loads(_get_text(s3, bucket, diag_parts[0]))
    assert diag["nonce"] == nonce, (
        f"the diagnostic must carry this run's own nonce; expected {nonce!r}, got {diag!r}"
    )
    assert [diag["rows"], diag["bad"]] == [_BAD_ROWS, _BAD_UNPARSEABLE], (
        f"the engine must really have read the CSV and really failed to parse one record against "
        f"the declared integer schema: expected {_BAD_ROWS} records of which {_BAD_UNPARSEABLE} "
        f"unparseable, the driver reported {diag!r}"
    )

    final_state = _poll(
        lambda: _cluster()["Status"]["State"],
        lambda s: s in TERMINAL_CLUSTER_STATES,
        timeout_s=900, interval_s=_POLL_S, ctx=ctx,
        description=(f"cluster {cluster_id} reaching a terminal state after its TERMINATE_CLUSTER "
                     f"step failed"),
    )
    assert final_state == "TERMINATED_WITH_ERRORS", (
        f"a TERMINATE_CLUSTER step failure must end the cluster in TERMINATED_WITH_ERRORS; got "
        f"{final_state!r}"
    )
    status = _cluster()["Status"]
    reason = status["StateChangeReason"]
    assert reason.get("Code") == "STEP_FAILURE", (
        f"a cluster terminated by a failing step must report StateChangeReason.Code STEP_FAILURE; "
        f"got {reason!r}"
    )
    assert reason.get("Message") == "Shut down as step failed", (
        f"StateChangeReason must carry the message naming the cause; got {reason!r}"
    )
    cluster_end = status["Timeline"].get("EndDateTime")
    boom_end = boom["Status"]["Timeline"].get("EndDateTime")
    assert cluster_end is not None and boom_end is not None, (
        f"both the step and the cluster must publish EndDateTime so cause can be ordered before "
        f"effect; step {boom['Status']['Timeline']!r}, cluster {status['Timeline']!r}"
    )
    assert cluster_end >= boom_end, (
        f"the cluster ended at {cluster_end} but the step that terminated it only finished at "
        f"{boom_end} — the shutdown cannot precede its own cause"
    )

    out_keys = _keys_under(s3, bucket, f"{_OUT_PREFIX}/")
    assert out_keys == [_CONTROL_KEY], (
        f"the failing Spark job must have left NO output: s3://{bucket}/{_OUT_PREFIX}/ must hold "
        f"exactly the control object written earlier. Expected [{_CONTROL_KEY!r}], got {out_keys!r}"
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
