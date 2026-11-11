"""spark-partitioned-input-pruned-then-written-back-partitioned."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "spark-partitioned-input-pruned-then-written-back-partitioned"
GROUP = "data-plane"
SERVICES = ["emr"]

_SCENARIO = "emr-spark-partition-prune"
_PREFIX = "sim2real-behav-emrpp-"

_ROWS = 300
# Expected per-group count and sum of `id % 3` over 1..300, derived from the grouping's definition.
_GROUPS = {
    f"p{r}": (
        len([i for i in range(1, _ROWS + 1) if i % 3 == r]),
        sum(i for i in range(1, _ROWS + 1) if i % 3 == r),
    )
    for r in (0, 1, 2)
}
_PRUNED_KEY = "p1"
_PROBE_ID = 7
_PROBE_GROUP = f"p{_PROBE_ID % 3}"
# A partition value no row can land in, so "the read really happened and really came back empty" is
# an observed number rather than a swallowed error.
_ABSENT_KEY = "p9"

_JOB_KEY = "job/partition_prune.py"
_IN_PREFIX = "input"
_OUT_PREFIX = "output"
_REPORT_PREFIX = "report"

# One script, two modes, so the writer and the reader are provably the same bytes uploaded once.
# The reader emits ONE json line the harness compares against values Python computed above.
_SPARK_JOB = '''\
import json
import sys

from pyspark.sql import SparkSession

mode, base, nonce, rows, probe = sys.argv[1:6]
rows = int(rows)
in_uri = base + "/IN_PREFIX"
out_uri = base + "/OUT_PREFIX"
spark = SparkSession.builder.appName("sim2real-emr-partition-prune").getOrCreate()

if mode == "write":
    df = spark.range(1, rows + 1).selectExpr(
        "id as id",
        "concat('" + nonce + "-', cast(id as string)) as label",
        "concat('p', cast(id % 3 as string)) as part",
    )
    df.write.mode("overwrite").partitionBy("part").parquet(in_uri)
else:
    root = spark.read.parquet(in_uri)
    # The partition column is recovered from the PATH here...
    root_cols = sorted(root.columns)
    root_types = dict((f.name, f.dataType.simpleString()) for f in root.schema)
    # ...and must be absent from the bytes of a leaf data file read on its own.
    leaf = sorted(root.inputFiles())[0]
    leaf_cols = sorted(spark.read.parquet(leaf).columns)

    root.createOrReplaceTempView("rows")
    grouped = spark.sql("select part, count(1) as n, sum(id) as s from rows group by part")
    groups = dict((r["part"], [r["n"], r["s"]]) for r in grouped.collect())

    pruned = root.where("part = 'PRUNED_KEY'")
    pruned_row = pruned.selectExpr("count(1) as n", "sum(id) as s").collect()[0]
    absent_n = root.where("part = 'ABSENT_KEY'").count()

    probe_rows = root.where("id = " + probe).collect()
    probe_label = probe_rows[0]["label"] if probe_rows else "NOROW"
    probe_part = probe_rows[0]["part"] if probe_rows else "NOROW"

    # The partitioned OUTPUT: derived aggregate rows, written back under the same partitioning.
    spark.sql("select part, count(1) as n, sum(id) as total from rows group by part") \\
        .write.mode("overwrite").partitionBy("part").parquet(out_uri)

    report = {
        "root_cols": root_cols,
        "root_types": root_types,
        "leaf": leaf,
        "leaf_cols": leaf_cols,
        "groups": groups,
        "pruned_n": pruned_row["n"],
        "pruned_s": pruned_row["s"],
        "absent_n": absent_n,
        "probe_label": probe_label,
        "probe_part": probe_part,
    }
    spark.sparkContext.parallelize([json.dumps(report, sort_keys=True)], 1) \\
        .saveAsTextFile(base + "/REPORT_PREFIX")

spark.stop()
'''.replace("IN_PREFIX", _IN_PREFIX).replace("OUT_PREFIX", _OUT_PREFIX) \
   .replace("REPORT_PREFIX", _REPORT_PREFIX) \
   .replace("PRUNED_KEY", _PRUNED_KEY).replace("ABSENT_KEY", _ABSENT_KEY)


INSTANCE_TYPE = "m5.xlarge"
# Pinned to 6.x: from emr-7.10.0 S3A replaces EMRFS as the default s3:// connector, which changes
# what `fs.s3.impl` resolves to and which committer writes.
# (https://docs.aws.amazon.com/emr/latest/ReleaseGuide/emr-s3a-migrate.html)
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
# AmazonElasticMapReduceRole, NOT AmazonEMRServicePolicy_v2: v2 only grants access to network
# resources tagged `for-use-with-amazon-emr-managed-policies`, including EMR's managed groups.
_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
# Grants the cluster's EC2 instances the S3 access that makes the data plane below reachable at all.
_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"

_CLUSTER_GONE_CODES = (
    "InvalidRequestException", "ClusterNotFound", "ResourceNotFoundException",
    "EntityNotFoundException",
)
TERMINAL_STEP_STATES = {"COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"}
TERMINAL_CLUSTER_STATES = {"TERMINATED", "TERMINATED_WITH_ERRORS"}


def _swallow(fn):
    """Run fn(), swallowing any exception. TEARDOWN ONLY — never on an assertion path."""
    try:
        fn()
    except Exception:  # noqa: BLE001 — best-effort teardown
        pass


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


def _delete_with_retry(fn, attempts=60, delay=2, ctx=None):
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

    Created in-check: EMR_DefaultRole / EMR_EC2_DefaultRole need not exist in the account.
    """
    iam = ctx.client("iam")
    svc_role = ctx.unique_name(_PREFIX + "svc-")
    ec2_role = ctx.unique_name(_PREFIX + "ec2-")

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

    # IAM eventual consistency: wait, bounded, until IAM reports the profile carrying its role.
    # RunJobFlow's own bounded retry covers the remaining propagation to EMR.
    deadline = time.monotonic() + 60
    while not iam.get_instance_profile(InstanceProfileName=ec2_role)["InstanceProfile"]["Roles"]:
        if time.monotonic() >= deadline:
            raise AssertionError(f"instance profile {ec2_role} did not list its role within 60s")
        time.sleep(2)
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

    EMR has no ClusterNotFound code: a reaped cluster describes as InvalidRequestException ("is not
    valid"). A throttle or 5xx must not be read as termination.
    """
    code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
    return code in _CLUSTER_GONE_CODES or "is not valid" in str(exc)


def _terminate_and_await_teardown(emr, cluster_id, ctx=None):
    """Terminate and WAIT: EMR needs the service role for the whole wind-down, and cleanups run
    LIFO with the IAM deletions registered first, so a bare terminate strands the EC2 fleet."""
    _swallow(lambda: emr.set_termination_protection(
        JobFlowIds=[cluster_id], TerminationProtected=False))
    _swallow(lambda: emr.terminate_job_flows(JobFlowIds=[cluster_id]))
    last = None
    deadline = _teardown_deadline(ctx, _CLEANUP_BUDGET_S)
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


def _run_cluster(emr, ctx, service_role, job_flow_role, **params):
    """RunJobFlow, retrying only transient IAM-propagation / throttle errors, registering the
    terminate-and-wait teardown immediately after the id exists."""
    last = None
    resp = None
    deadline = time.monotonic() + _budget_s(ctx, 320)
    while True:
        try:
            resp = _run_job_flow_propagated(ctx, emr, ServiceRole=service_role, JobFlowRole=job_flow_role, **params)
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
            time.sleep(2)
    if resp is None:
        raise AssertionError(f"RunJobFlow never succeeded: {last}")
    cluster_id = resp["JobFlowId"]
    ctx.on_cleanup(lambda: _terminate_and_await_teardown(emr, cluster_id, ctx=ctx))
    return cluster_id


def _instances(subnet, keep_alive=True, core=0):
    """One primary, optionally `core` core nodes. KeepJobFlowAliveWhenNoSteps=True by default so the
    only thing that can end the cluster is the teardown: an ALL_STEPS_COMPLETED auto-shutdown would
    race the S3 reads the assertions depend on."""
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
    """Every step on the cluster, keyed by Name. Paginated: a single-page read is not a bound."""
    return {
        s["Name"]: s
        for page in emr.get_paginator("list_steps").paginate(ClusterId=cluster_id)
        for s in page["Steps"]
    }


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


def _partition_layout(keys, prefix):
    """Split `<prefix>/...` keys into (partition dir -> data keys, other keys directly under it)."""
    parts: dict[str, list[str]] = {}
    other: list[str] = []
    for key in keys:
        rest = key[len(prefix) + 1:]
        head, _, tail = rest.partition("/")
        if tail and head.startswith("part="):
            parts.setdefault(head, []).append(key)
        else:
            other.append(rest)
    return parts, other



@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Spark step writes a Hive-partitioned dataset to S3; the next step prunes it by partition
    value (an absent value yields zero rows), aggregates, and writes a partitioned result back. Leaf
    files must not contain the partition column; layout and per-group numbers are read from S3.

    Reference: https://docs.aws.amazon.com/emr/latest/ReleaseGuide/emr-spark-submit-step.html
    Reference: https://docs.aws.amazon.com/emr/latest/ReleaseGuide/emr-fs.html
    """
    emr = ctx.client("emr")
    s3 = ctx.client("s3")

    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account, "STS must report the account id before any cluster is launched"

    bucket = _make_bucket(ctx, s3)
    service_role, job_flow_role = _ensure_emr_roles(ctx)
    subnet = _make_network(ctx)

    # The nonce exists only in this process, so a label carrying it can only have come from the
    # DataFrame this run wrote: no leftover or canned dataset can satisfy the probe leg.
    nonce = ctx.unique_name("pp-")
    s3.put_object(Bucket=bucket, Key=_JOB_KEY, Body=_SPARK_JOB.encode("utf-8"))
    base = f"s3://{bucket}"
    job_uri = f"s3://{bucket}/{_JOB_KEY}"

    def _spark_step(name, mode):
        return {
            "Name": name,
            "ActionOnFailure": "CONTINUE",
            "HadoopJarStep": {
                "Jar": "command-runner.jar",
                "Args": [
                    "spark-submit", "--deploy-mode", "client", job_uri,
                    mode, base, nonce, str(_ROWS), str(_PROBE_ID),
                ],
            },
        }

    write_name = "sim2real-partition-write"
    read_name = "sim2real-partition-read"

    cluster_id = _run_cluster(
        emr, ctx, service_role, job_flow_role,
        Name=ctx.unique_name(_PREFIX),
        ReleaseLabel=RELEASE_LABEL,
        LogUri=f"s3://{bucket}/logs/",
        Applications=[{"Name": "Hadoop"}, {"Name": "Spark"}],
        Instances=_instances(subnet, keep_alive=True, core=1),
        # 1, so the read step cannot start before the write step ends: the data dependency is the
        # subject, and overlapping the two would make the read's input a race.
        StepConcurrencyLevel=1,
        Steps=[_spark_step(write_name, "write"), _spark_step(read_name, "read")],
        VisibleToAllUsers=True,
        Tags=_TAGS,
    )

    submitted = _steps_by_name(emr, cluster_id)
    assert set(submitted) == {write_name, read_name}, (
        f"ListSteps must report exactly the two submitted steps "
        f"{sorted([write_name, read_name])!r}, got {sorted(submitted)!r}"
    )
    write_id, read_id = submitted[write_name]["Id"], submitted[read_name]["Id"]

    # One wait, on the LAST step: at StepConcurrencyLevel=1 the read step cannot reach a terminal
    # state until the write step has, so this covers both without a second budget.
    read_step = _await_step(
        emr, cluster_id, read_id, timeout_s=_budget_s(ctx, 1800),
        description=f"the partition-read step {read_id} on {cluster_id} reaches a terminal state",
        ctx=ctx,
    )
    write_step = emr.describe_step(ClusterId=cluster_id, StepId=write_id)["Step"]

    assert write_step["Status"]["State"] == "COMPLETED", (
        f"the partitioned WRITE step must COMPLETE; got {write_step['Status']['State']!r} "
        f"(reason {write_step['Status'].get('StateChangeReason')!r}, "
        f"details {write_step['Status'].get('FailureDetails')!r})"
    )
    assert read_step["Status"]["State"] == "COMPLETED", (
        f"the partition-read step must COMPLETE — a FAILED read here means the partitioned dataset "
        f"step 1 wrote was not readable. Got {read_step['Status']['State']!r} "
        f"(reason {read_step['Status'].get('StateChangeReason')!r}, "
        f"details {read_step['Status'].get('FailureDetails')!r})"
    )
    write_end = write_step["Status"]["Timeline"].get("EndDateTime")
    read_start = read_step["Status"]["Timeline"].get("StartDateTime")
    assert write_end is not None and read_start is not None, (
        f"both steps must carry a timeline so the data dependency is observable: write "
        f"{write_step['Status']['Timeline']!r}, read {read_step['Status']['Timeline']!r}"
    )
    assert write_end <= read_start, (
        f"at StepConcurrencyLevel=1 the reader must start ({read_start}) only after the writer "
        f"finished ({write_end}) — otherwise its input was a race, not a dependency"
    )

    # --- the INPUT layout, read independently out of S3 -------------------------------------------
    in_keys = _keys_under(s3, bucket, f"{_IN_PREFIX}/")
    in_parts, in_other = _partition_layout(in_keys, _IN_PREFIX)
    assert set(in_parts) == {f"part={g}" for g in _GROUPS}, (
        f"partitionBy('part') must lay out exactly one Hive-style directory per distinct value "
        f"{sorted('part=' + g for g in _GROUPS)!r} under s3://{bucket}/{_IN_PREFIX}/; got "
        f"{sorted(in_parts)!r} (all keys: {in_keys!r})"
    )
    assert in_other == ["_SUCCESS"], (
        f"the only non-partition entry directly under s3://{bucket}/{_IN_PREFIX}/ must be Spark's "
        f"_SUCCESS marker; got {in_other!r}"
    )
    for part, data_keys in sorted(in_parts.items()):
        assert data_keys and all(k.endswith(".parquet") for k in data_keys), (
            f"every data object under {part}/ must be a .parquet file written by the engine; got "
            f"{data_keys!r}"
        )
    residue = [k for k in in_keys if "_temporary" in k or k.endswith(".pending")]
    assert residue == [], (
        f"a committed write must leave no staging residue under s3://{bucket}/{_IN_PREFIX}/; "
        f"found {residue!r}"
    )

    # Real Parquet, not JSON wearing the suffix: the four-byte magic at the head of a leaf.
    probe_leaf = in_parts[f"part={_PROBE_GROUP}"][0]
    head = s3.get_object(Bucket=bucket, Key=probe_leaf, Range="bytes=0-3")["Body"].read()
    assert head == b"PAR1", (
        f"s3://{bucket}/{probe_leaf} must begin with the Parquet magic b'PAR1'; got {head!r}"
    )

    # --- the OUTPUT layout: the engine's own derived rows, partitioned the same way ----------------
    out_keys = _keys_under(s3, bucket, f"{_OUT_PREFIX}/")
    out_parts, out_other = _partition_layout(out_keys, _OUT_PREFIX)
    assert set(out_parts) == {f"part={g}" for g in _GROUPS}, (
        f"the aggregate the reader wrote back must itself be partitioned by 'part', one directory "
        f"per group {sorted('part=' + g for g in _GROUPS)!r}; got {sorted(out_parts)!r} "
        f"(all keys: {out_keys!r})"
    )
    assert out_other == ["_SUCCESS"], (
        f"the only non-partition entry directly under s3://{bucket}/{_OUT_PREFIX}/ must be the "
        f"_SUCCESS marker; got {out_other!r}"
    )

    # --- THE assertions: the numbers and the schema the engine reported --------------------------
    report_keys = _keys_under(s3, bucket, f"{_REPORT_PREFIX}/")
    parts = [k for k in report_keys if "/part-" in k]
    assert len(parts) == 1, (
        f"the reader must have written exactly one report part file under "
        f"s3://{bucket}/{_REPORT_PREFIX}/, got {report_keys!r}"
    )
    report = json.loads(_get_text(s3, bucket, parts[0]))

    expected_groups = {g: [n, s] for g, (n, s) in _GROUPS.items()}
    assert report["groups"] == expected_groups, (
        f"grouping the partitioned dataset by its partition column must reproduce the three "
        f"residue classes of id % 3 over 1..{_ROWS} exactly: expected {expected_groups!r} "
        f"(count, sum), the engine reported {report['groups']!r}"
    )
    assert sorted(report["root_cols"]) == ["id", "label", "part"], (
        f"reading the dataset ROOT must recover the partition column from the path alongside the "
        f"data columns: expected ['id', 'label', 'part'], got {report['root_cols']!r}"
    )
    assert "part" not in report["leaf_cols"], (
        f"the partition column must NOT be serialised into the data files — it lives in the path. "
        f"Reading the leaf {report['leaf']!r} on its own yielded {report['leaf_cols']!r}, which "
        f"still carries 'part': this engine stored the partition column as ordinary data"
    )
    assert sorted(report["leaf_cols"]) == ["id", "label"], (
        f"a leaf data file must carry exactly the two data columns; got {report['leaf_cols']!r}"
    )
    assert report["root_types"]["part"] == "string", (
        f"a non-numeric partition value must infer as StringType on read "
        f"(PartitioningUtils tries Null/Integer/Long/Decimal/Double/Date/Timestamp and falls back "
        f"to string); got {report['root_types']!r}"
    )

    pruned_n, pruned_s = _GROUPS[_PRUNED_KEY]
    assert [report["pruned_n"], report["pruned_s"]] == [pruned_n, pruned_s], (
        f"a predicate on the PARTITION column must select exactly the rows of "
        f"part={_PRUNED_KEY}/: expected count {pruned_n} and sum {pruned_s}, the engine reported "
        f"count {report['pruned_n']!r} and sum {report['pruned_s']!r}"
    )
    assert report["absent_n"] == 0, (
        f"a predicate naming the partition value {_ABSENT_KEY!r}, for which no directory exists, "
        f"must select ZERO rows; the engine reported {report['absent_n']!r} — it is not resolving "
        f"the predicate against the partition layout at all"
    )
    assert report["probe_label"] == f"{nonce}-{_PROBE_ID}", (
        f"the probed row must carry the label this run's own nonce produced: expected "
        f"{nonce + '-' + str(_PROBE_ID)!r}, got {report['probe_label']!r}"
    )
    assert report["probe_part"] == _PROBE_GROUP, (
        f"row id={_PROBE_ID} must be recovered from the {_PROBE_GROUP!r} partition directory; the "
        f"engine reported {report['probe_part']!r}"
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
