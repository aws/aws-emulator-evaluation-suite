"""spark-defaults-classification-governs-the-shuffle-partition-count."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "spark-defaults-classification-governs-the-shuffle-partition-count"
GROUP = "data-plane"
SERVICES = ["emr"]

_SCENARIO = "emr-spark-defaults-effect"
_PREFIX = "sim2real-behav-emrsd-"

# 7 because it is nowhere near Spark's own default of 200, is small enough that every partition can
# be filled, and is not a power of two (so it cannot be produced by an accidental default).
_SHUFFLE_PARTITIONS = 7
# Far more distinct grouping keys than partitions, so hash distribution leaves no partition empty
# and the part-file count can be asserted exactly.
_GROUP_KEYS = 210
_ROWS = 4200
_JOB_KEY = "job/shuffle_conf.py"
_AGG_PREFIX = "agg"
_REPORT_PREFIX = "report"

_SPARK_JOB = '''\
import sys

from pyspark.sql import SparkSession

base, nonce_key, rows, keys = sys.argv[1:5]
rows = int(rows)
keys = int(keys)
spark = SparkSession.builder.appName("sim2real-emr-shuffle-conf").getOrCreate()

configured = spark.conf.get("spark.sql.shuffle.partitions", "UNSET")
nonce_value = spark.conf.get(nonce_key, "UNSET")

# A real shuffle: groupBy forces an exchange, and the resulting DataFrame is repartitioned to
# spark.sql.shuffle.partitions.
src = spark.range(0, rows, 1, 3).selectExpr("id %% %d as k" % keys, "id as v")
agg = src.groupBy("k").sum("v")
observed_partitions = agg.rdd.getNumPartitions()
agg.write.mode("overwrite").json(base + "/AGG_PREFIX")

report = "%s|%s|%d" % (configured, nonce_value, observed_partitions)
spark.sparkContext.parallelize([report], 1).saveAsTextFile(base + "/REPORT_PREFIX")
spark.stop()
'''.replace("AGG_PREFIX", _AGG_PREFIX).replace("REPORT_PREFIX", _REPORT_PREFIX)

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
# The legacy service policy deliberately, NOT AmazonEMRServicePolicy_v2: v2 only grants EMR access
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

    # IAM eventual consistency is bounded in _run_cluster's own retry-on-transient loop below
    # (matches "invalid instanceprofile" / "invalid ec2"), not by a flat sleep here.
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
        # CreateBucket rejects an explicit LocationConstraint for us-east-1 itself; this is the
        # API's own quirk, not an assumption about which region the check runs in.
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
    LIFO with the IAM deletions registered first, so a bare terminate strands the EC2 fleet.

    Raises if the cluster has not reached a terminal state by the deadline, so a stuck cluster is
    reported rather than left running and silently passed as torn down.
    """
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
            time.sleep(2)
            continue
        if state in TERMINAL_CLUSTER_STATES:
            return
        time.sleep(2)
    raise AssertionError(
        f"cluster {cluster_id} did not reach a terminal state by the cleanup deadline; last state {state!r}"
    )


def _run_cluster(emr, ctx, service_role, job_flow_role, **params):
    """RunJobFlow, retrying only transient IAM-propagation / throttle errors, registering the
    terminate-and-wait teardown immediately after the id exists."""
    last = None
    resp = None
    deadline = time.monotonic() + 320.0
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
            last = exc
            time.sleep(2)
    if resp is None:
        raise AssertionError(f"RunJobFlow never succeeded: {last}")
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


def _await_step(ctx, emr, cluster_id, step_id, *, timeout_s, description):
    """Wait for one step to reach a TERMINAL state and return the described step."""
    return _poll(
        ctx,
        lambda: emr.describe_step(ClusterId=cluster_id, StepId=step_id)["Step"],
        lambda s: s["Status"]["State"] in TERMINAL_STEP_STATES,
        timeout_s=timeout_s,
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
    equalities and absence assertions, which is the polarity B8 sanctions."""
    return sorted(
        o["Key"]
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix)
        for o in page.get("Contents", [])
    )


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A `spark-defaults` Configurations block does not merely echo back from DescribeCluster: it
    reaches the SparkSession inside a submitted step AND governs the engine's behaviour, so a
    shuffled DataFrame lands in exactly the configured number of partitions and writes that many objects.

    Reference: https://docs.aws.amazon.com/emr/latest/ReleaseGuide/emr-spark-configure.html
    Reference: https://repost.aws/knowledge-center/emr-set-spark-parameters
    """
    emr = ctx.client("emr")
    s3 = ctx.client("s3")

    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account, "STS must report the caller's account id before any cluster is launched"

    bucket = _make_bucket(ctx, s3)
    service_role, job_flow_role = _ensure_emr_roles(ctx)
    subnet = _pick_subnet(ctx)

    nonce = ctx.unique_name("sd-")
    # A property key no Spark release knows, so its value can only have come from OUR block.
    nonce_key = f"spark.sim2real.{nonce}"
    s3.put_object(Bucket=bucket, Key=_JOB_KEY, Body=_SPARK_JOB.encode("utf-8"))
    base = f"s3://{bucket}"

    configurations = [{
        "Classification": "spark-defaults",
        "Properties": {
            "spark.sql.shuffle.partitions": str(_SHUFFLE_PARTITIONS),
            # AQE coalesces small post-shuffle partitions (down to 1, on this dataset size)
            # regardless of spark.sql.shuffle.partitions. Disabling it is what makes the
            # submitted count the exact, deterministic post-shuffle partition count.
            "spark.sql.adaptive.coalescePartitions.enabled": "false",
            nonce_key: nonce,
        },
    }]

    step_name = "sim2real-shuffle-conf"
    cluster_id = _run_cluster(
        emr, ctx, service_role, job_flow_role,
        Name=ctx.unique_name(_PREFIX),
        ReleaseLabel=RELEASE_LABEL,
        LogUri=f"s3://{bucket}/logs/",
        Applications=[{"Name": "Hadoop"}, {"Name": "Spark"}],
        Configurations=configurations,
        Instances=_instances(subnet, keep_alive=True, core=1),
        StepConcurrencyLevel=1,
        Steps=[{
            "Name": step_name,
            "ActionOnFailure": "CONTINUE",
            "HadoopJarStep": {
                "Jar": "command-runner.jar",
                "Args": [
                    "spark-submit", "--deploy-mode", "client", f"s3://{bucket}/{_JOB_KEY}",
                    base, nonce_key, str(_ROWS), str(_GROUP_KEYS),
                ],
            },
        }],
        VisibleToAllUsers=True,
        Tags=_TAGS,
    )

    # --- the control-plane leg first, so a target that never stored the block is separable from one
    # that stored it and ignored it.
    described = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]
    echoed = [
        c for c in described.get("Configurations", [])
        if c.get("Classification") == "spark-defaults"
    ]
    assert len(echoed) == 1, (
        f"DescribeCluster must echo exactly the one submitted spark-defaults classification, got "
        f"{described.get('Configurations')!r}"
    )
    props = echoed[0].get("Properties", {})
    assert props.get("spark.sql.shuffle.partitions") == str(_SHUFFLE_PARTITIONS), (
        f"the echoed spark-defaults block must carry the submitted shuffle-partition count: "
        f"expected {str(_SHUFFLE_PARTITIONS)!r}, got "
        f"{props.get('spark.sql.shuffle.partitions')!r} from {props!r}"
    )
    assert props.get(nonce_key) == nonce, (
        f"the echoed spark-defaults block must carry this run's nonce property {nonce_key!r}="
        f"{nonce!r}, got {props.get(nonce_key)!r} from {props!r}"
    )

    submitted = _steps_by_name(emr, cluster_id)
    assert set(submitted) == {step_name}, (
        f"ListSteps must report exactly the one submitted step, got {sorted(submitted)!r}"
    )
    step = _await_step(
        ctx, emr, cluster_id, submitted[step_name]["Id"], timeout_s=1800,
        description=f"the shuffle-config step on {cluster_id} reaches a terminal state",
    )
    assert step["Status"]["State"] == "COMPLETED", (
        f"the shuffle-config step must COMPLETE; got {step['Status']['State']!r} "
        f"(reason {step['Status'].get('StateChangeReason')!r})"
    )

    # --- THE assertion: what the ENGINE saw, and what it then did, read out of S3.
    report_keys = _keys_under(s3, bucket, f"{_REPORT_PREFIX}/")
    report_parts = [k for k in report_keys if "/part-" in k]
    assert len(report_parts) == 1, (
        f"the step must have written exactly one report part file under "
        f"s3://{bucket}/{_REPORT_PREFIX}/, got {report_keys!r}"
    )
    fields = _get_text(s3, bucket, report_parts[0]).split("|")
    assert len(fields) == 3, (
        f"the report line must be configured|nonce|observed_partitions, got {fields!r}"
    )
    got_configured, got_nonce, got_partitions = fields

    assert got_nonce == nonce, (
        f"the SparkSession must see this run's nonce property {nonce_key!r}: expected {nonce!r}, "
        f"the engine reported {got_nonce!r} — 'UNSET' means the spark-defaults classification never "
        f"reached /etc/spark/conf/spark-defaults.conf"
    )
    assert got_configured == str(_SHUFFLE_PARTITIONS), (
        f"the SparkSession must see the SUBMITTED shuffle-partition count: expected "
        f"{str(_SHUFFLE_PARTITIONS)!r}, the engine reported {got_configured!r} (Spark's own default "
        f"is 200, so that value means the classification was ignored)"
    )
    assert int(got_partitions) == _SHUFFLE_PARTITIONS, (
        f"the configuration must GOVERN the engine, not merely be readable by it: a post-shuffle "
        f"DataFrame must land in {_SHUFFLE_PARTITIONS} partitions, the engine reported "
        f"{got_partitions!r}"
    )

    # --- and the effect is visible at the destination, counted through a different operation.
    agg_keys = _keys_under(s3, bucket, f"{_AGG_PREFIX}/")
    assert f"{_AGG_PREFIX}/_SUCCESS" in agg_keys, (
        f"a completed Spark write must leave a _SUCCESS marker at s3://{bucket}/{_AGG_PREFIX}/; "
        f"keys were {agg_keys!r}"
    )
    part_keys = [k for k in agg_keys if k.rsplit("/", 1)[-1].startswith("part-")]
    assert len(part_keys) == _SHUFFLE_PARTITIONS, (
        f"writing a {_SHUFFLE_PARTITIONS}-partition DataFrame must produce "
        f"{_SHUFFLE_PARTITIONS} part objects under s3://{bucket}/{_AGG_PREFIX}/, got "
        f"{len(part_keys)}: {part_keys!r}"
    )

    # The aggregate must also be RIGHT, so "7 files" cannot be satisfied by 7 empty ones.
    seen_groups = 0
    for key in part_keys:
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode("utf-8")
        for line in body.splitlines():
            if line.strip():
                seen_groups += 1
    assert seen_groups == _GROUP_KEYS, (
        f"the shuffled group-by must emit one row per distinct key: expected {_GROUP_KEYS} groups "
        f"across {len(part_keys)} part files, counted {seen_groups}"
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
