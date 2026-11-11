"""parquet-written-by-one-spark-step-is-read-back-by-the-next."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "parquet-written-by-one-spark-step-is-read-back-by-the-next"
GROUP = "data-plane"
SERVICES = ["emr"]

_SCENARIO = "emr-parquet-step-roundtrip"
_PREFIX = "sim2real-behav-emrpq-"

_ROWS = 1000
# Closed form, computed here rather than pinned.
_ID_SUM = _ROWS * (_ROWS + 1) // 2
_PROBE_ID = 7
_JOB_KEY = "job/parquet_roundtrip.py"
_DATA_PREFIX = "parquet"
_ANSWER_PREFIX = "answer"

# One script, two modes, so the writer and the reader are provably the same code shipped once. The
# reader emits a single pipe-joined line the harness compares against values it computed in Python.
_SPARK_JOB = '''\
import sys

from pyspark.sql import SparkSession
from pyspark.sql.types import BooleanType, LongType, StringType, StructField, StructType

mode, base, nonce, rows = sys.argv[1:5]
rows = int(rows)
data_uri = base + "/PARQUET_PREFIX"
spark = SparkSession.builder.appName("sim2real-emr-parquet-roundtrip").getOrCreate()

if mode == "write":
    schema = StructType([
        StructField("id", LongType(), False),
        StructField("label", StringType(), False),
        StructField("flag", BooleanType(), False),
    ])
    data = [(i, nonce + "-" + str(i), i % 2 == 0) for i in range(1, rows + 1)]
    df = spark.createDataFrame(data, schema)
    df.write.mode("overwrite").partitionBy("flag").parquet(data_uri)
else:
    back = spark.read.parquet(data_uri)
    n = back.count()
    total = back.selectExpr("sum(id) as s").collect()[0]["s"]
    types = ",".join(
        "%s:%s" % (f.name, f.dataType.simpleString()) for f in sorted(back.schema, key=lambda f: f.name)
    )
    probe = back.where("id = " + sys.argv[5]).collect()
    label = probe[0]["label"] if probe else "NOROW"
    flag = str(probe[0]["flag"]).lower() if probe else "NOROW"
    body = "%d|%d|%s|%s|%s" % (n, total, types, label, flag)
    spark.sparkContext.parallelize([body], 1).saveAsTextFile(base + "/ANSWER_PREFIX")

spark.stop()
'''.replace("PARQUET_PREFIX", _DATA_PREFIX).replace("ANSWER_PREFIX", _ANSWER_PREFIX)


INSTANCE_TYPE = "m5.xlarge"
# Pinned to the 6.x line ON PURPOSE. From emr-7.10.0 the S3A filesystem replaces EMRFS as the
# default s3:// connector for every scheme
# (https://docs.aws.amazon.com/emr/latest/ReleaseGuide/emr-s3a-migrate.html), which changes what
# `fs.s3.impl` resolves to and which committer writes.
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
# The v1 service policy deliberately, NOT AmazonEMRServicePolicy_v2: v2 only grants EMR access
# to network resources carrying the `for-use-with-amazon-emr-managed-policies` tag, which would make
# the check depend on the account's default VPC being pre-tagged.
_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
# Grants the cluster's EC2 instances the S3 (and Glue catalog) access that makes the data plane
# below reachable at all.
_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"

_CLUSTER_GONE_CODES = (
    "InvalidRequestException", "ClusterNotFound", "ResourceNotFoundException",
    "EntityNotFoundException",
)
# Throttle codes the EMR JSON protocol returns; the EMR model declares no throttle error of its own.
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException")
TERMINAL_STEP_STATES = {"COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"}
TERMINAL_CLUSTER_STATES = {"TERMINATED", "TERMINATED_WITH_ERRORS"}
BAD_CLUSTER_STATES = {"TERMINATED_WITH_ERRORS", "INTERNAL_ERROR"}

# Written by a step when a read it was told to attempt found nothing. A literal the check controls,
# so "the read really happened and really came back empty" is an observable value rather than a
# swallowed error.
_MISSING = "MISSING"


def _swallow(fn):
    """Run fn(), swallowing any exception. TEARDOWN ONLY — never on an assertion path."""
    try:
        fn()
    except Exception:  # noqa: BLE001 — best-effort teardown
        pass


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

    return svc_role, ec2_role


def _pick_subnet(ctx):
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
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _TAGS})
    return bucket


def _cluster_is_gone(exc):
    """True only for the error that means the cluster no longer exists.

    EMR has no ClusterNotFound code: describing a reaped cluster comes back as
    InvalidRequestException ("Cluster id 'j-...' is not valid"). Throttling, a socket timeout or a
    brief 5xx must NOT be read as termination — over a 900s wait a transient is far likelier than a
    genuine disappearance, and treating one as "gone" hands the IAM deletions a cluster that is
    still assuming the service role.
    """
    code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
    return code in _CLUSTER_GONE_CODES or "is not valid" in str(exc)


def _terminate_and_await_teardown(emr, cluster_id, ctx=None):
    """Terminate and WAIT: EMR needs the service role for the whole wind-down, and cleanups run
    LIFO with the IAM deletions registered first, so a bare terminate strands the EC2 fleet."""
    _swallow(lambda: emr.set_termination_protection(
        JobFlowIds=[cluster_id], TerminationProtected=False))
    _swallow(lambda: emr.terminate_job_flows(JobFlowIds=[cluster_id]))
    deadline = _teardown_deadline(ctx, _CLEANUP_BUDGET_S)
    state = None
    while time.monotonic() < deadline:
        try:
            state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        except Exception as exc:  # noqa: BLE001 — teardown classification only
            if _cluster_is_gone(exc):
                return
            code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
            if code not in _THROTTLE_CODES:
                raise
            time.sleep(2)
            continue
        if state in TERMINAL_CLUSTER_STATES:
            return
        time.sleep(2)
    raise RuntimeError(f"cluster {cluster_id} did not reach a terminal state by the cleanup deadline; last state {state!r}")


def _run_cluster(emr, ctx, service_role, job_flow_role, **params):
    """RunJobFlow through the propagation retry, registering the terminate-and-wait teardown
    immediately after the id exists."""
    resp = _run_job_flow_propagated(
        ctx, emr, ServiceRole=service_role, JobFlowRole=job_flow_role, **params
    )
    cluster_id = resp["JobFlowId"]
    ctx.on_cleanup(lambda: _terminate_and_await_teardown(emr, cluster_id, ctx=ctx))
    return cluster_id


def _instances(subnet, keep_alive=True, core=0):
    """One primary, optionally `core` core nodes. KeepJobFlowAliveWhenNoSteps=True by default so
    the only thing that can end the cluster is the teardown: an ALL_STEPS_COMPLETED auto-shutdown
    would race the S3 reads the assertions depend on."""
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


def _await_step(emr, cluster_id, step_id, *, timeout_s, description):
    """Wait for one step to reach a TERMINAL state and return the described step."""
    return _poll(
        lambda: emr.describe_step(ClusterId=cluster_id, StepId=step_id)["Step"],
        lambda s: s["Status"]["State"] in TERMINAL_STEP_STATES,
        timeout_s=timeout_s,
        interval_s=20,
        description=description,
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
    """Every key under a prefix. `.get("Contents", [])` is correct here: it feeds exact set/count
    equalities and absence assertions."""
    return sorted(
        o["Key"]
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix)
        for o in page.get("Contents", [])
    )


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Parquet dataset written by one Spark step is read back by the next step on the same cluster with
    the exact row count, SUM, column types and a probed row, and the S3 bytes carry the PAR1 magic:
    inter-step data flow through S3 only works on a backend that really runs and persists the jobs.
    """
    emr = ctx.client("emr")
    s3 = ctx.client("s3")

    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account, "STS must report the caller's account id before any cluster is launched"

    bucket = _make_bucket(ctx, s3)
    service_role, job_flow_role = _ensure_emr_roles(ctx)
    subnet = _pick_subnet(ctx)

    # The nonce exists only in this process, so a label carrying it can only have come from the
    # DataFrame this run wrote — no canned or leftover dataset can satisfy the probe leg.
    nonce = ctx.unique_name("pq-")
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

    write_name = "sim2real-parquet-write"
    read_name = "sim2real-parquet-read"

    cluster_id = _run_cluster(
        emr, ctx, service_role, job_flow_role,
        Name=ctx.unique_name(_PREFIX),
        ReleaseLabel=RELEASE_LABEL,
        LogUri=f"s3://{bucket}/logs/",
        Applications=[{"Name": "Hadoop"}, {"Name": "Spark"}],
        Instances=_instances(subnet, keep_alive=True, core=1),
        # 1 so the two steps are strictly sequential: the read step must not start before the write
        # step ends, which is the ordering the data dependency is asserted against.
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
    # state until the write step has, so waiting on it covers both without a second budget.
    read_step = _await_step(
        emr, cluster_id, read_id, timeout_s=1800,
        description=f"the parquet-read step {read_id} on {cluster_id} reaches a terminal state",
    )
    write_step = emr.describe_step(ClusterId=cluster_id, StepId=write_id)["Step"]

    assert write_step["Status"]["State"] == "COMPLETED", (
        f"the parquet WRITE step must COMPLETE; got {write_step['Status']['State']!r} "
        f"(reason {write_step['Status'].get('StateChangeReason')!r}, "
        f"details {write_step['Status'].get('FailureDetails')!r})"
    )
    assert read_step["Status"]["State"] == "COMPLETED", (
        f"the parquet READ step must COMPLETE — a FAILED read here means the dataset step 1 wrote "
        f"was not there. Got {read_step['Status']['State']!r} "
        f"(reason {read_step['Status'].get('StateChangeReason')!r})"
    )

    # The ordering the data dependency rests on, from the target's own timeline.
    w_end = write_step["Status"]["Timeline"].get("EndDateTime")
    r_start = read_step["Status"]["Timeline"].get("StartDateTime")
    assert w_end is not None and r_start is not None, (
        f"both steps must carry an execution window; write EndDateTime={w_end!r}, "
        f"read StartDateTime={r_start!r}"
    )
    assert r_start >= w_end, (
        f"at StepConcurrencyLevel=1 the read step cannot start ({r_start}) before the write step "
        f"ended ({w_end}) — without that ordering the round-trip proves nothing"
    )

    # --- THE assertion: what the READER recovered, read independently out of S3.
    answer_keys = _keys_under(s3, bucket, f"{_ANSWER_PREFIX}/")
    parts = [k for k in answer_keys if "/part-" in k]
    assert len(parts) == 1, (
        f"the read step must have written exactly one answer part file under "
        f"s3://{bucket}/{_ANSWER_PREFIX}/, got {answer_keys!r}"
    )
    fields = _get_text(s3, bucket, parts[0]).split("|")
    assert len(fields) == 5, (
        f"the answer line must be rows|sum|types|label|flag, got {fields!r}"
    )
    got_rows, got_sum, got_types, got_label, got_flag = fields

    assert int(got_rows) == _ROWS, (
        f"re-reading the Parquet dataset must recover every row written: expected {_ROWS}, "
        f"Spark counted {got_rows!r}"
    )
    assert int(got_sum) == _ID_SUM, (
        f"re-reading the Parquet dataset must recover the exact SUM(id): expected {_ID_SUM} "
        f"(closed form {_ROWS}*({_ROWS}+1)/2), Spark computed {got_sum!r}"
    )
    assert got_label == f"{nonce}-{_PROBE_ID}", (
        f"the row with id={_PROBE_ID} must carry the label this run generated: expected "
        f"{nonce}-{_PROBE_ID}, got {got_label!r} — a wrong label means the reader saw a different "
        f"dataset than the writer wrote"
    )

    # --- the schema must survive the format, not just the values. For the `flag` partition
    # column, Spark's partition-value type inference tries
    # Null/Integer/Long/Decimal/Double/Date/Timestamp and falls back to StringType for anything
    # else, so a BooleanType column written through partitionBy() always reads back as "string",
    # as it does on emr-6.15.0.
    expected_types = "flag:string,id:bigint,label:string"
    assert got_types == expected_types, (
        f"the Parquet round-trip must preserve column types: expected {expected_types!r} (a "
        f"boolean partition column is never re-inferred as boolean; it stays a string), Spark "
        f"reported {got_types!r} (a `string` where `bigint` belongs means the writer or the reader "
        f"is not really columnar)"
    )
    expected_flag = "true" if _PROBE_ID % 2 == 0 else "false"
    assert got_flag == expected_flag, (
        f"the partition column must round-trip as the string Spark's partition-value inference "
        f"produced: id={_PROBE_ID} is {'even' if _PROBE_ID % 2 == 0 else 'odd'} so flag must read "
        f"back {expected_flag!r}, got {got_flag!r}"
    )

    # --- the S3 layout, read at the destination with a different operation than the write.
    data_keys = _keys_under(s3, bucket, f"{_DATA_PREFIX}/")
    assert f"{_DATA_PREFIX}/_SUCCESS" in data_keys, (
        f"a completed Spark Parquet write must leave a _SUCCESS marker at "
        f"s3://{bucket}/{_DATA_PREFIX}/; keys were {data_keys!r}"
    )
    data_files = [k for k in data_keys if not k.rsplit("/", 1)[-1].startswith("_")]
    assert data_files, (
        f"the Parquet write produced no data objects under s3://{bucket}/{_DATA_PREFIX}/; "
        f"keys were {data_keys!r}"
    )
    assert all(k.endswith(".parquet") for k in data_files), (
        f"every Parquet data object must be named *.parquet, got {data_files!r}"
    )
    partition_dirs = {k.split("/")[1] for k in data_files if len(k.split("/")) > 2}
    assert partition_dirs == {"flag=true", "flag=false"}, (
        f"partitionBy('flag') must lay out Hive-style partition directories "
        f"{{'flag=true', 'flag=false'}}, got {sorted(partition_dirs)!r} from {data_files!r}"
    )
    assert not any(k.startswith(f"{_DATA_PREFIX}/_temporary/") for k in data_keys), (
        f"a successful commit must leave no _temporary staging prefix behind; keys were "
        f"{data_keys!r}"
    )

    # --- and the bytes must be real Parquet. A Range GET of 4 bytes at each end: the format's magic
    # number, which only a columnar writer emits.
    for key in data_files:
        head = s3.get_object(Bucket=bucket, Key=key, Range="bytes=0-3")["Body"].read()
        size = s3.head_object(Bucket=bucket, Key=key)["ContentLength"]
        tail = s3.get_object(
            Bucket=bucket, Key=key, Range=f"bytes={size - 4}-{size - 1}"
        )["Body"].read()
        assert head == b"PAR1" and tail == b"PAR1", (
            f"s3://{bucket}/{key} is not a Parquet file: the format requires the four bytes "
            f"b'PAR1' at both ends, got head={head!r} tail={tail!r} (size {size})"
        )


def _run_job_flow_propagated(ctx, emr, **params):
    """RunJobFlow, retrying every 2 s while it is refused for a transient reason: throttling, or IAM
    not yet having propagated this run's new roles or instance profile to EMR. The retry ends at
    min(320 s, the check's time left); every other refusal raises."""
    from botocore.exceptions import ClientError

    left = ctx.time_left()
    deadline = time.monotonic() + (320.0 if left is None else min(320.0, left))
    while True:
        try:
            return emr.run_job_flow(**params)
        except ClientError as exc:
            err = exc.response["Error"]
            low = err.get("Message", "").lower()
            transient = (
                "throttl" in low
                or "rate exceeded" in low
                or "invalid instanceprofile" in low
                or "invalid ec2" in low
                or (err["Code"] == "AccessDeniedException"
                    and "failed to authorize instance profile" in low)
            )
            if not transient or time.monotonic() >= deadline:
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
    its interfaces to release, clear then delete every non-default group (EMR's groups reference each other),
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
