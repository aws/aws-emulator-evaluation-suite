"""scaling-emrfs-read-of-a-deleted-object-is-rejected-and-writes-no-output."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "scaling-emrfs-read-of-a-deleted-object-is-rejected-and-writes-no-output"
GROUP = "data-plane"
SERVICES = ["emr"]

_SCENARIO = "emr-emrfs-delete-visibility"
_PREFIX = "sim2real-behav-emrdv-"

_KEEP_KEY = "data/keep.txt"
_DOOMED_KEY = "data/doomed.txt"
_PROBE_KEY = "probe/overwrite.txt"
_JOB_KEY = "job/consume.py"
_KEEP_OUT = "out/keep"
_DOOMED_OUT = "out/doomed"

# The payload the consumer aggregates: the integers 1..50, one per line, written through EMRFS.
_N_LINES = 50
_PAYLOAD = "\n".join(str(i) for i in range(1, _N_LINES + 1))
_EXPECTED_SUM = _N_LINES * (_N_LINES + 1) // 2

# Two generations of the same EMRFS path. Distinct lengths as well as distinct bytes, so a target
# that serves a cached first generation cannot pass on a byte-count coincidence.
_GEN1 = "generation-one"
_GEN2 = "generation-two-longer"

# The check creates and owns its own VPC/subnet/IGW/route: a freshly provisioned account need not
# have a default VPC.

INSTANCE_TYPE = "m5.xlarge"
# Pinned to the 6.x line ON PURPOSE: from emr-7.10.0 the S3A filesystem replaces EMRFS as the
# default s3:// connector for every scheme, which changes what `fs.s3.impl` resolves to and which
# code path the deletes and reads below travel.
RELEASE_LABEL = "emr-6.15.0"
_EMRFS_IMPL = "com.amazon.ws.emr.hadoop.fs.EmrFileSystem"

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
# The v1 service policy deliberately, NOT AmazonEMRServicePolicy_v2: v2 only grants EMR access
# to network resources carrying the `for-use-with-amazon-emr-managed-policies` tag, which would make
# the check depend on the account's VPC being pre-tagged.
_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
# Grants the cluster's EC2 instances the S3 access that makes the data plane below reachable at all.
_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"

_CLUSTER_GONE_CODES = (
    "InvalidRequestException", "ClusterNotFound", "ResourceNotFoundException",
    "EntityNotFoundException",
)
TERMINAL_STEP_STATES = {"COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"}
TERMINAL_CLUSTER_STATES = {"TERMINATED", "TERMINATED_WITH_ERRORS"}

# The Spark consumer. Deliberately NOT an f-string: both paths arrive on argv. `collect()` is what
# forces the input resolution, so a deleted input fails the ACTION and saveAsTextFile is never
# reached — which is what makes "writes no output" an observable rather than an assumption.
_SPARK_CONSUMER = '''import sys

from pyspark.sql import SparkSession

in_uri = sys.argv[1]
out_uri = sys.argv[2]

spark = SparkSession.builder.appName("sim2real-emrfs-consume").getOrCreate()
sc = spark.sparkContext
rows = sc.textFile(in_uri).map(lambda line: int(line.strip())).collect()
sc.parallelize(["%d %d" % (len(rows), sum(rows))], 1).saveAsTextFile(out_uri)
spark.stop()
'''


def _gone(fn, *codes):
    """Run a teardown call; return quietly only on the given not-found codes, raise the rest."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in codes:
            raise


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(probe, predicate, *, timeout_s, interval_s, description, ctx=None):
    """Poll probe() until predicate(result); RAISE on timeout (never return the last value)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _error_code(fn):
    """The AWS error code fn() raises. RAISES if fn() unexpectedly succeeds, so a served deleted
    object reads as a failed assertion rather than an error-code mismatch."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001 — the code is the assertion's subject
        response = getattr(exc, "response", None) or {}
        return response.get("Error", {}).get("Code") or type(exc).__name__
    raise AssertionError(
        f"the call was expected to fail because its target no longer exists, but it succeeded "
        f"and returned {result!r}"
    )


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

    EMR_DefaultRole / EMR_EC2_DefaultRole do not exist in a fresh account, so they are created here.
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

    # IAM eventual consistency: poll IAM's own read path for the new instance profile, bounded with
    # a deadline, rather than an unconditional sleep.
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
    """True only for the error that means the cluster no longer exists: EMR has no ClusterNotFound
    code, a reaped cluster describes as InvalidRequestException. A throttle or 5xx is not "gone"."""
    code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
    return code in _CLUSTER_GONE_CODES or "is not valid" in str(exc)


def _terminate_and_await_teardown(ctx, run_state: dict, emr, cluster_id):
    """Terminate and WAIT: EMR needs the service role for the whole wind-down, and cleanups run
    LIFO with the IAM deletions registered first, so a bare terminate strands the EC2 fleet."""
    _gone(lambda: emr.set_termination_protection(
        JobFlowIds=[cluster_id], TerminationProtected=False), "ValidationException", "InvalidRequestException")
    _gone(lambda: emr.terminate_job_flows(JobFlowIds=[cluster_id]), "InvalidRequestException")
    last = None
    deadline = min(time.monotonic() + 900, _cleanup_deadline(ctx, run_state))
    while time.monotonic() < deadline:
        try:
            state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        except Exception as exc:  # noqa: BLE001 — teardown classification only
            if _cluster_is_gone(exc):
                return
            last = exc
            time.sleep(2)
            continue
        if state in TERMINAL_CLUSTER_STATES:
            return
        last = state
        time.sleep(2)
    raise RuntimeError(f"EMR cluster {cluster_id} was not deleted: {last!r}")


def _run_cluster(emr, ctx, run_state: dict, service_role, job_flow_role, **params):
    """RunJobFlow, retrying only transient IAM-propagation / throttle errors, registering the
    terminate-and-wait teardown immediately after the id exists."""
    last = None
    resp = None
    deadline = time.monotonic() + _budget_s(ctx, 320)
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
                if transient and _budget_spent(ctx):
                    raise TimeoutError("RunJobFlow succeeding: the run budget ended first; not graded")
                raise
            last = exc
            time.sleep(2)
    if resp is None:
        raise AssertionError(f"RunJobFlow never succeeded: {last}")
    cluster_id = resp["JobFlowId"]
    ctx.on_cleanup(lambda: _terminate_and_await_teardown(ctx, run_state, emr, cluster_id))
    return cluster_id


def _instances(subnet):
    """One primary and one core node. KeepJobFlowAliveWhenNoSteps=True so the only thing that can
    end the cluster is the teardown: an ALL_STEPS_COMPLETED auto-shutdown would race the S3 reads
    the assertions depend on."""
    return {
        "InstanceGroups": [
            {"Name": "sim2real-primary", "InstanceRole": "MASTER",
             "InstanceType": INSTANCE_TYPE, "InstanceCount": 1, "Market": "ON_DEMAND"},
            {"Name": "sim2real-core", "InstanceRole": "CORE",
             "InstanceType": INSTANCE_TYPE, "InstanceCount": 1, "Market": "ON_DEMAND"},
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


def _await_step(emr, cluster_id, step_id, *, timeout_s, description, ctx=None):
    """Wait for one step to reach a TERMINAL state and return the described step."""
    return _poll(
        lambda: emr.describe_step(ClusterId=cluster_id, StepId=step_id)["Step"],
        lambda s: s["Status"]["State"] in TERMINAL_STEP_STATES,
        timeout_s=timeout_s,
        interval_s=2,
        description=description,
        ctx=ctx,
    )


def _steps_by_name(emr, cluster_id):
    """Every step on the cluster, keyed by Name. Hard-subscripted by the caller."""
    return {
        s["Name"]: s
        for page in emr.get_paginator("list_steps").paginate(ClusterId=cluster_id)
        for s in page["Steps"]
    }


def _get_text(s3, bucket, key):
    """Read an object as text. No try/except: a missing key must fail loudly, not degrade."""
    return s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode("utf-8").strip()


def _keys_under(s3, bucket, prefix):
    """Every key under a prefix; empty when there are none."""
    return sorted(
        o["Key"]
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix)
        for o in page.get("Contents", [])
    )


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A Spark job whose EMRFS input was just deleted fails and writes no output, while the same job
    over the surviving sibling writes `50 1275`; EMRFS reads, overwrites and deletes are immediately
    visible to EMRFS and to S3 (HeadObject 404), with no convergence loop.

    Reference: https://docs.aws.amazon.com/emr/latest/ReleaseGuide/emr-fs.html
    Reference: https://docs.aws.amazon.com/emr/latest/ReleaseGuide/emr-s3a-migrate.html
    """
    # Per-run state: the teardown deadline, the private network and the clusters placed in it.
    run_state: dict = {}
    emr = ctx.client("emr")
    s3 = ctx.client("s3")

    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account, "STS must report the account id before any cluster is launched"

    bucket = _make_bucket(ctx, s3)
    service_role, job_flow_role = _ensure_emr_roles(ctx)
    subnet = _pick_subnet(ctx, run_state)
    region = ctx.region

    s3.put_object(Bucket=bucket, Key=_JOB_KEY, Body=_SPARK_CONSUMER.encode("utf-8"))

    doomed_uri = f"s3://{bucket}/{_DOOMED_KEY}"
    keep_uri = f"s3://{bucket}/{_KEEP_KEY}"

    # Step 1: write both objects through EMRFS, read each straight back, overwrite the probe and read
    # it back, then delete exactly one object and immediately try to read it. `hadoop fs -mkdir -p`
    # first: EMRFS enforces HDFS-style parent-directory-exists semantics on `-put`.
    mutate_script = (
        f"set -eu; "
        f"hdfs getconf -confKey fs.s3.impl > /tmp/impl; "
        f"seq 1 {_N_LINES} > /tmp/nums; "
        f"printf %s '{_GEN1}' > /tmp/gen1; printf %s '{_GEN2}' > /tmp/gen2; "
        f"hadoop fs -mkdir -p s3://{bucket}/data; "
        f"hadoop fs -mkdir -p s3://{bucket}/probe; "
        f"hadoop fs -put /tmp/nums {keep_uri}; "
        f"hadoop fs -put /tmp/nums {doomed_uri}; "
        f"hadoop fs -cat {keep_uri} > /tmp/raw_keep; "
        f"hadoop fs -cat {doomed_uri} > /tmp/raw_doomed; "
        f"hadoop fs -put /tmp/gen1 s3://{bucket}/{_PROBE_KEY}; "
        f"hadoop fs -cat s3://{bucket}/{_PROBE_KEY} > /tmp/read1; "
        f"hadoop fs -put -f /tmp/gen2 s3://{bucket}/{_PROBE_KEY}; "
        f"hadoop fs -cat s3://{bucket}/{_PROBE_KEY} > /tmp/read2; "
        f"hadoop fs -rm -skipTrash {doomed_uri}; "
        f"rc=0; hadoop fs -cat {doomed_uri} > /tmp/cat_after_delete 2>/dev/null || rc=$?; "
        f"printf %s \"$rc\" > /tmp/rc_cat; "
        f"for f in impl raw_keep raw_doomed read1 read2 cat_after_delete rc_cat; do "
        f"aws s3 cp /tmp/$f s3://{bucket}/report/$f.txt --region {region}; done"
    )

    # Step 2: the same application twice, differing only in the input path. No `set -e`: the second
    # spark-submit is EXPECTED to fail, and its exit status is the observable.
    # EMR configures spark-submit to run on YARN by default.
    consume_script = (
        f"set -u; "
        f"aws s3 cp s3://{bucket}/{_JOB_KEY} /tmp/consume.py --region {region}; "
        f"rc_keep=0; rc_doomed=0; "
        f"spark-submit --deploy-mode client /tmp/consume.py "
        f"{keep_uri} s3://{bucket}/{_KEEP_OUT} > /tmp/keep_log 2>&1 || rc_keep=$?; "
        f"spark-submit --deploy-mode client /tmp/consume.py "
        f"{doomed_uri} s3://{bucket}/{_DOOMED_OUT} > /tmp/doomed_log 2>&1 || rc_doomed=$?; "
        f"printf %s \"$rc_keep\" > /tmp/rc_keep; "
        f"printf %s \"$rc_doomed\" > /tmp/rc_doomed; "
        f"grep -F '{doomed_uri}' /tmp/doomed_log | head -3 > /tmp/doomed_hits || true; "
        f"tail -c 3000 /tmp/doomed_log > /tmp/doomed_tail; "
        f"for f in rc_keep rc_doomed doomed_hits doomed_tail; do "
        f"aws s3 cp /tmp/$f s3://{bucket}/report/$f.txt --region {region}; done"
    )

    mutate_name = "sim2real-emrfs-mutate"
    consume_name = "sim2real-emrfs-consume"

    cluster_id = _run_cluster(
        emr, ctx, run_state, service_role, job_flow_role,
        Name=ctx.unique_name(_PREFIX),
        ReleaseLabel=RELEASE_LABEL,
        LogUri=f"s3://{bucket}/logs/",
        Applications=[{"Name": "Hadoop"}, {"Name": "Spark"}],
        Instances=_instances(subnet),
        StepConcurrencyLevel=1,
        Steps=[
            _shell_step(mutate_name, mutate_script),
            _shell_step(consume_name, consume_script),
        ],
        VisibleToAllUsers=True,
        Tags=_TAGS,
    )

    submitted = _steps_by_name(emr, cluster_id)
    assert set(submitted) == {mutate_name, consume_name}, (
        f"ListSteps must report exactly the two submitted steps, got {sorted(submitted)!r}"
    )
    mutate_id, consume_id = submitted[mutate_name]["Id"], submitted[consume_name]["Id"]

    consume_step = _await_step(
        emr, cluster_id, consume_id, timeout_s=_budget_s(ctx, 1800),
        description=f"the consumer step {consume_id} on {cluster_id} reaches a terminal state",
        ctx=ctx,
    )
    mutate_step = emr.describe_step(ClusterId=cluster_id, StepId=mutate_id)["Step"]

    assert mutate_step["Status"]["State"] == "COMPLETED", (
        f"the EMRFS mutate step must COMPLETE — under `set -eu` a FAILED step here is a failed "
        f"put, read-back, overwrite or delete. Got {mutate_step['Status']['State']!r} "
        f"(reason {mutate_step['Status'].get('StateChangeReason')!r}, "
        f"failure {mutate_step['Status'].get('FailureDetails')!r})"
    )
    assert consume_step["Status"]["State"] == "COMPLETED", (
        f"the consumer step wraps both spark-submits and must COMPLETE regardless of their exit "
        f"statuses; got {consume_step['Status']['State']!r} "
        f"(reason {consume_step['Status'].get('StateChangeReason')!r}, "
        f"failure {consume_step['Status'].get('FailureDetails')!r})"
    )

    # --- the writes really went through EMRFS, not through some other S3 client.
    impl = _get_text(s3, bucket, "report/impl.txt")
    assert impl == _EMRFS_IMPL, (
        f"on {RELEASE_LABEL} the cluster's fs.s3.impl must resolve to EMRFS: expected "
        f"{_EMRFS_IMPL!r}, the cluster reported {impl!r}"
    )

    # --- read-after-write through EMRFS, same step, no retry: the documented contract.
    assert _get_text(s3, bucket, "report/raw_keep.txt") == _PAYLOAD, (
        f"EMRFS must serve back exactly what `hadoop fs -put` just wrote to {_KEEP_KEY}; got "
        f"{_get_text(s3, bucket, 'report/raw_keep.txt')!r}"
    )
    assert _get_text(s3, bucket, "report/raw_doomed.txt") == _PAYLOAD, (
        f"EMRFS must serve back exactly what `hadoop fs -put` just wrote to {_DOOMED_KEY} — the "
        f"deletion below only means something if the object was really there; got "
        f"{_get_text(s3, bucket, 'report/raw_doomed.txt')!r}"
    )

    # --- an overwrite is immediately visible, and the previous generation is NOT served.
    read1 = _get_text(s3, bucket, "report/read1.txt")
    read2 = _get_text(s3, bucket, "report/read2.txt")
    assert read1 == _GEN1, (
        f"the first EMRFS read of {_PROBE_KEY} must serve the first generation {_GEN1!r}, got "
        f"{read1!r}"
    )
    assert read2 == _GEN2, (
        f"the EMRFS read immediately after `hadoop fs -put -f` must serve the SECOND generation "
        f"{_GEN2!r} with no convergence loop; got {read2!r} — {_GEN1!r} here would mean a stale "
        f"read of a replaced object"
    )
    probe_via_api = _get_text(s3, bucket, _PROBE_KEY)
    assert probe_via_api == _GEN2, (
        f"the AWS S3 API must agree that {_PROBE_KEY} now holds the second generation: expected "
        f"{_GEN2!r}, got {probe_via_api!r}"
    )

    # --- the delete is immediately visible to EMRFS: non-zero status and ZERO bytes.
    rc_cat = _get_text(s3, bucket, "report/rc_cat.txt")
    assert rc_cat.isdigit(), f"the cat-after-delete step must report a numeric status, got {rc_cat!r}"
    assert int(rc_cat) != 0, (
        f"`hadoop fs -cat` of an object deleted moments earlier through EMRFS must fail; it exited "
        f"{rc_cat} (0 would mean EMRFS served a deleted object)"
    )
    cat_bytes = s3.get_object(Bucket=bucket, Key="report/cat_after_delete.txt")["Body"].read()
    assert cat_bytes == b"", (
        f"the failed EMRFS read must have emitted no bytes at all; it emitted {cat_bytes!r}"
    )

    # --- and to the AWS S3 API, with an exact code. The surviving sibling proves it was targeted.
    code = _error_code(lambda: s3.head_object(Bucket=bucket, Key=_DOOMED_KEY))
    assert code == "404", (
        f"HeadObject on the deleted key {_DOOMED_KEY} must answer exactly '404'; got {code!r}"
    )
    assert _get_text(s3, bucket, _KEEP_KEY) == _PAYLOAD, (
        f"the `hadoop fs -rm` must have deleted ONLY {_DOOMED_KEY}: {_KEEP_KEY} must still hold the "
        f"payload, got {_get_text(s3, bucket, _KEEP_KEY)!r}"
    )

    # --- THE negative: the job over the deleted input is rejected and writes NOTHING.
    rc_doomed = _get_text(s3, bucket, "report/rc_doomed.txt")
    assert rc_doomed.isdigit(), f"the failing spark-submit must report a numeric status, got {rc_doomed!r}"
    assert int(rc_doomed) != 0, (
        f"spark-submit over the deleted input {doomed_uri} must exit non-zero; it exited "
        f"{rc_doomed}. Tail of its own log: "
        f"{_get_text(s3, bucket, 'report/doomed_tail.txt')[-600:]!r}"
    )
    doomed_out_keys = _keys_under(s3, bucket, _DOOMED_OUT + "/")
    assert doomed_out_keys == [], (
        f"the rejected job must leave its output prefix {_DOOMED_OUT}/ completely empty — no part "
        f"file and no _SUCCESS marker; found {doomed_out_keys!r}"
    )
    hits = _get_text(s3, bucket, "report/doomed_hits.txt")
    assert doomed_uri in hits, (
        f"the failing job's own log must name the input path it could not resolve; grep for "
        f"{doomed_uri!r} produced {hits!r}. Tail of the log: "
        f"{_get_text(s3, bucket, 'report/doomed_tail.txt')[-600:]!r}"
    )

    # --- the positive control, in the same step on the same cluster: it works when the object is
    # there, which is what makes the absence above attributable to the deletion.
    rc_keep = _get_text(s3, bucket, "report/rc_keep.txt")
    assert rc_keep == "0", (
        f"positive control: the identical spark-submit over the surviving input {keep_uri} must "
        f"exit 0; it exited {rc_keep!r}"
    )
    keep_out_keys = _keys_under(s3, bucket, _KEEP_OUT + "/")
    parts = [k for k in keep_out_keys if k.startswith(f"{_KEEP_OUT}/part-")]
    assert f"{_KEEP_OUT}/_SUCCESS" in keep_out_keys, (
        f"positive control: the surviving job's EMRFS commit must leave a _SUCCESS marker under "
        f"{_KEEP_OUT}/; keys were {keep_out_keys!r}"
    )
    assert len(parts) == 1, (
        f"positive control: the single-partition write must land exactly one part file under "
        f"{_KEEP_OUT}/; got {parts!r}"
    )
    aggregate = _get_text(s3, bucket, parts[0])
    assert aggregate == f"{_N_LINES} {_EXPECTED_SUM}", (
        f"positive control: the surviving job must have read all {_N_LINES} lines written through "
        f"EMRFS and summed them to {_EXPECTED_SUM}; it wrote {aggregate!r}"
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
