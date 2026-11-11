"""on-cluster-add-partition-lands-in-the-glue-catalog."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "on-cluster-add-partition-lands-in-the-glue-catalog"
GROUP = "resource-binding"
SERVICES = ["emr", "glue"]

_SCENARIO = "emr-glue-add-partition"
_PREFIX = "sim2real-behav-emrgp-"

# The hive-site classification that makes the Glue Data Catalog the metastore.
_GLUE_HIVE_SITE = {
    "Classification": "hive-site",
    "Properties": {
        "hive.metastore.client.factory.class":
            "com.amazonaws.glue.catalog.metastore.AWSGlueDataCatalogHiveClientFactory",
        "hive.metastore.schema.verification": "false",
    },
}

_PARTITION_VALUE = "2026-01-02"
_ABSENT_PARTITION_VALUE = "2099-12-31"
_ROWS = ["1,alpha", "2,beta", "3,gamma", "4,delta"]
_DATA_PREFIX = "data"


INSTANCE_TYPE = "m5.xlarge"
# Pinned to 6.x: from emr-7.10.0 S3A replaces EMRFS as the default s3:// connector
# (https://docs.aws.amazon.com/emr/latest/ReleaseGuide/emr-s3a-migrate.html).
RELEASE_LABEL = "emr-6.15.0"

_PARTITION_NOT_FOUND = "Cannot find partition."

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
TERMINAL_STEP_STATES = {"COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"}
TERMINAL_CLUSTER_STATES = {"TERMINATED", "TERMINATED_WITH_ERRORS"}
BAD_CLUSTER_STATES = {"TERMINATED_WITH_ERRORS", "INTERNAL_ERROR"}

# Written by a step when a read it was told to attempt found nothing. A literal the check controls,
# so "the read really happened and really came back empty" is an observable value rather than a
# swallowed error.
_MISSING = "MISSING"


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

    # IAM eventual consistency; RunJobFlow's transient retry is the real backstop.
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            iam.get_instance_profile(InstanceProfileName=ec2_role)
            break
        except Exception:  # noqa: BLE001 — prerequisite polling only, never an assertion
            time.sleep(2)
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

    EMR has no ClusterNotFound: a reaped cluster gives InvalidRequestException "... is not valid".
    """
    code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
    return code in _CLUSTER_GONE_CODES or "is not valid" in str(exc)


def _terminate_and_await_teardown(ctx, emr, cluster_id):
    """Terminate and WAIT: EMR needs the service role for the whole wind-down, and cleanups run
    LIFO with the IAM deletions registered first, so a bare terminate strands the EC2 fleet."""
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
            time.sleep(2)
    if resp is None:
        raise AssertionError(f"RunJobFlow never succeeded: {last}")
    cluster_id = resp["JobFlowId"]
    ctx.on_cleanup(lambda: _terminate_and_await_teardown(ctx, emr, cluster_id))
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
    """Every step on the cluster, keyed by Name."""
    return {
        s["Name"]: s
        for page in emr.get_paginator("list_steps").paginate(ClusterId=cluster_id)
        for s in page["Steps"]
    }


def _get_text(s3, bucket, key):
    """Read an object as text. No try/except: a missing key must fail loudly, not degrade."""
    return s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode("utf-8").strip()


def _keys_under(s3, bucket, prefix):
    """Every key under a prefix; S3 omits Contents when the prefix is empty."""
    return sorted(
        o["Key"]
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix)
        for o in page.get("Contents", [])
    )




def _partition_values(glue, database, table):
    """Every partition value tuple Glue holds for the table."""
    return sorted(
        tuple(p["Values"])
        for page in glue.get_paginator("get_partitions").paginate(
            DatabaseName=database, TableName=table)
        for p in page.get("Partitions", [])
    )


def _hive_step_script(statement, bucket, key, region):
    """A shell step that runs one HiveQL statement and ships its combined output to S3.

    `hive -S` (silent) so the last non-empty stdout line is the result and not a progress banner.
    `set -eu` so a Hive failure cannot be mistaken for an empty result. `2>&1` so a failing DDL's
    diagnostic reaches S3 and lands in the assertion message instead of being lost.
    """
    if '"' in statement:
        # A guard on this file's own constants, not an assertion about the target.
        raise ValueError(
            f"a HiveQL statement passed to `hive -e` must use only single-quoted literals, "
            f"got {statement!r}"
        )
    return (
        "set -eu; "
        f'hive -S -e "{statement}" > /tmp/hive_out.txt 2>&1; '
        f"aws s3 cp /tmp/hive_out.txt s3://{bucket}/{key} --region {region}"
    )


def _error(fn, *, description):
    """Call fn() expecting a ClientError and RETURN its (code, message). RAISES on unexpected
    success, so an over-permissive target's acceptance never reads as a code mismatch."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001 — the error IS the subject; its code is extracted
        err = (getattr(exc, "response", None) or {}).get("Error", {})
        return err.get("Code", ""), err.get("Message")
    raise AssertionError(f"{description} unexpectedly SUCCEEDED, returning {result!r}")

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Hive ADD PARTITION on an EMR cluster using the Glue Data Catalog creates the partition in
    Glue: GetPartition finds it at the named location (and still refuses a never-added value),
    and Hive then counts the rows behind it.

    Reference: https://docs.aws.amazon.com/emr/latest/ReleaseGuide/emr-hive-metastore-glue.html
    """
    emr = ctx.client("emr")
    s3 = ctx.client("s3")
    glue = ctx.client("glue")

    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account, "STS must report the caller's account id before any cluster is launched"

    bucket = _make_bucket(ctx, s3)
    service_role, job_flow_role = _ensure_emr_roles(ctx)
    subnet = _pick_subnet(ctx)

    # The data, and the catalog entry that does NOT yet know about its partition.
    partition_prefix = f"{_DATA_PREFIX}/dt={_PARTITION_VALUE}"
    partition_uri = f"s3://{bucket}/{partition_prefix}"
    s3.put_object(
        Bucket=bucket,
        Key=f"{partition_prefix}/rows.csv",
        Body=("\n".join(_ROWS) + "\n").encode("utf-8"),
    )

    database = ctx.unique_name("sim2real_emrgp_db_").replace("-", "_").lower()
    table = ctx.unique_name("sim2real_emrgp_tbl_").replace("-", "_").lower()
    glue.create_database(DatabaseInput={"Name": database})
    ctx.on_cleanup(lambda: glue.delete_database(Name=database))
    glue.create_table(
        DatabaseName=database,
        TableInput={
            "Name": table,
            "TableType": "EXTERNAL_TABLE",
            "Parameters": {"EXTERNAL": "TRUE", "classification": "csv"},
            "PartitionKeys": [{"Name": "dt", "Type": "string"}],
            "StorageDescriptor": {
                "Columns": [{"Name": "id", "Type": "int"}, {"Name": "name", "Type": "string"}],
                "Location": f"s3://{bucket}/{_DATA_PREFIX}/",
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat":
                    "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary":
                        "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                    "Parameters": {"field.delim": ","},
                },
            },
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=database, Name=table))

    # Before: Glue holds no partitions, so the after-state is a real delta.
    before = _partition_values(glue, database, table)
    assert before == [], (
        f"the freshly created table {database}.{table} must hold no partitions before the cluster "
        f"runs its DDL, got {before!r}"
    )
    absent_code, absent_message = _error(
        lambda: glue.get_partition(
            DatabaseName=database, TableName=table, PartitionValues=[_PARTITION_VALUE]),
        description=f"GetPartition for dt={_PARTITION_VALUE} before the DDL step ran",
    )
    assert absent_code == "EntityNotFoundException", (
        f"GetPartition for an unregistered partition must fail with EntityNotFoundException, got "
        f"{absent_code!r}"
    )
    assert absent_message == _PARTITION_NOT_FOUND, (
        f"GetPartition for an unregistered partition must say {_PARTITION_NOT_FOUND!r}, got "
        f"{absent_message!r}"
    )

    cluster_id = _run_cluster(
        emr, ctx, service_role, job_flow_role,
        Name=ctx.unique_name(_PREFIX),
        ReleaseLabel=RELEASE_LABEL,
        LogUri=f"s3://{bucket}/logs/",
        Applications=[{"Name": "Hadoop"}, {"Name": "Hive"}],
        Configurations=[_GLUE_HIVE_SITE],
        Instances=_instances(subnet, keep_alive=True, core=1),
        StepConcurrencyLevel=1,
        VisibleToAllUsers=True,
        Tags=_TAGS,
    )

    state = _poll(
        lambda: emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"],
        lambda s: s == "WAITING" or s in BAD_CLUSTER_STATES,
        timeout_s=_budget_s(ctx, 1500),
        interval_s=2,
        ctx=ctx,
        description=f"cluster {cluster_id} reaching WAITING with Hive installed",
    )
    assert state == "WAITING", (
        f"the cluster must reach WAITING before any DDL can be submitted; got {state!r}"
    )

    region = ctx.region
    # HiveQL literals are single-quoted, so the double-quoted `hive -e` wrapper needs no escaping.
    ddl = (
        f"ALTER TABLE {database}.{table} ADD PARTITION (dt='{_PARTITION_VALUE}') "
        f"LOCATION '{partition_uri}/';"
    )
    count_query = (
        f"SELECT count(*) FROM {database}.{table} WHERE dt='{_PARTITION_VALUE}';"
    )
    ddl_script = _hive_step_script(ddl, bucket, "results/ddl.txt", region)
    count_script = _hive_step_script(count_query, bucket, "results/count.txt", region)

    ddl_name = "sim2real-hive-add-partition"
    count_name = "sim2real-hive-count-partition"
    emr.add_job_flow_steps(JobFlowId=cluster_id, Steps=[
        _shell_step(ddl_name, ddl_script),
        _shell_step(count_name, count_script),
    ])

    submitted = _steps_by_name(emr, cluster_id)
    assert set(submitted) == {ddl_name, count_name}, (
        f"ListSteps must report exactly the two submitted steps, got {sorted(submitted)!r}"
    )
    count_step = _await_step(
        emr, cluster_id, submitted[count_name]["Id"], timeout_s=_budget_s(ctx, 900),
        description=f"the Hive count step on {cluster_id} reaches a terminal state",
        ctx=ctx,
    )
    ddl_step = emr.describe_step(
        ClusterId=cluster_id, StepId=submitted[ddl_name]["Id"])["Step"]

    assert ddl_step["Status"]["State"] == "COMPLETED", (
        f"the ADD PARTITION step must COMPLETE; got {ddl_step['Status']['State']!r} "
        f"(reason {ddl_step['Status'].get('StateChangeReason')!r}). A failure here usually means the "
        f"instance profile lacks the Glue catalog write actions"
    )
    assert count_step["Status"]["State"] == "COMPLETED", (
        f"the count step must COMPLETE; got {count_step['Status']['State']!r} "
        f"(reason {count_step['Status'].get('StateChangeReason')!r})"
    )

    # Glue now holds the partition the cluster created.
    after = _partition_values(glue, database, table)
    assert after == [(_PARTITION_VALUE,)], (
        f"after the cluster's ADD PARTITION, Glue must hold exactly the one partition "
        f"[('{_PARTITION_VALUE}',)] for {database}.{table}; got {after!r} (before it was {before!r})"
    )
    got = glue.get_partition(
        DatabaseName=database, TableName=table, PartitionValues=[_PARTITION_VALUE])["Partition"]
    location = got["StorageDescriptor"]["Location"]
    assert location.rstrip("/") == partition_uri.rstrip("/"), (
        f"the partition Glue holds must point at the prefix the Hive DDL named: expected "
        f"{partition_uri!r} (trailing slash ignored), got {location!r}"
    )
    assert got["TableName"] == table and got["DatabaseName"] == database, (
        f"the partition must belong to {database}.{table}, Glue reports "
        f"{got.get('DatabaseName')!r}.{got.get('TableName')!r}"
    )

    # Negative control: GetPartition still refuses a value that was never added.
    still_absent, still_absent_message = _error(
        lambda: glue.get_partition(
            DatabaseName=database, TableName=table,
            PartitionValues=[_ABSENT_PARTITION_VALUE]),
        description=f"GetPartition for dt={_ABSENT_PARTITION_VALUE}, which no DDL ever added",
    )
    assert still_absent == "EntityNotFoundException", (
        f"GetPartition for dt={_ABSENT_PARTITION_VALUE} must still fail with "
        f"EntityNotFoundException after the DDL added a DIFFERENT partition, got {still_absent!r}"
    )
    assert still_absent_message == _PARTITION_NOT_FOUND, (
        f"GetPartition for dt={_ABSENT_PARTITION_VALUE} must say {_PARTITION_NOT_FOUND!r}, got "
        f"{still_absent_message!r}"
    )

    # The engine really reads the data behind the partition it registered.
    count_text = _get_text(s3, bucket, "results/count.txt")
    lines = [ln.strip() for ln in count_text.splitlines() if ln.strip()]
    assert lines, (
        f"the Hive count step produced no output at s3://{bucket}/results/count.txt; "
        f"raw was {count_text!r}"
    )
    assert lines[-1] == str(len(_ROWS)), (
        f"Hive must count the {len(_ROWS)} rows behind the partition it just registered: expected "
        f"{len(_ROWS)!r}, the last output line was {lines[-1]!r} (full output {count_text!r})"
    )


# ===== private network =====
#: The check's own VPC: its clusters sit in a subnet with no internet route; a gateway endpoint to
#: S3 and an interface endpoint to Glue (the metastore the cluster calls) are the only ways out.
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
    offers instance_type, its Glue endpoint available; its teardown is registered before any
    cluster is placed in it."""
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
    group = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-glue-endpoint-"), VpcId=vpc_id,
        Description="HTTPS from the VPC to the Glue endpoint",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tags}])["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=group, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
        "IpRanges": [{"CidrIp": _PRIVATE_VPC_CIDR}]}])
    endpoint = ec2.create_vpc_endpoint(
        VpcId=vpc_id, VpcEndpointType="Interface", SubnetIds=[subnet_id], SecurityGroupIds=[group],
        ServiceName=f"com.amazonaws.{ec2.meta.region_name}.glue", PrivateDnsEnabled=True,
        TagSpecifications=[{"ResourceType": "vpc-endpoint", "Tags": tags}])["VpcEndpoint"]["VpcEndpointId"]
    deadline = time.monotonic() + min(300.0, ctx.time_left() or 300.0)
    while True:
        state = ec2.describe_vpc_endpoints(VpcEndpointIds=[endpoint])["VpcEndpoints"][0]["State"]
        if state.lower() == "available":
            break
        assert state.lower() == "pending" and time.monotonic() < deadline, (
            f"Glue endpoint {endpoint} is {state!r}, not available")
        time.sleep(2)
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
