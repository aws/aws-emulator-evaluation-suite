"""emr-spark-step-on-an-unregistered-glue-table-fails."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "emr-spark-step-on-an-unregistered-glue-table-fails"
GROUP = "errors"
SERVICES = ["emr", "glue"]

INSTANCE_TYPE = "m5.xlarge"
RELEASE_LABEL = "emr-6.15.0"

_SCENARIO = "emr-glue-metastore"
_TAGS = [
    {"Key": "sim2real", "Value": _SCENARIO},
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-xsvc"},
]

_EMR_SERVICE_TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "elasticmapreduce.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)
_EC2_TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)
_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"
# Granted explicitly: a missing Glue grant would fail the step exactly like the asserted defect.
_GLUE_READ_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "glue:GetDatabase",
                    "glue:GetDatabases",
                    "glue:GetTable",
                    "glue:GetTables",
                    "glue:GetPartition",
                    "glue:GetPartitions",
                    "glue:GetUserDefinedFunction",
                    "glue:GetUserDefinedFunctions",
                ],
                "Resource": "*",
            }
        ],
    }
)

_STEP_TERMINAL = {
    "COMPLETED",
    "FAILED",
    "CANCELLED",
    "INTERRUPTED",
    "TERMINATED_WITH_ERRORS",
    "INTERNAL_ERROR",
}
_CLUSTER_GONE_CODES = (
    "InvalidRequestException",
    "ClusterNotFound",
    "ResourceNotFoundException",
    "EntityNotFoundException",
)

# The CSV behind the Glue table; the asserted row counts derive from these.
_ALPHA_ROWS = 41
_BETA_ROWS = 96
_TOTAL_ROWS = _ALPHA_ROWS + _BETA_ROWS  # 137

# Two counts: the total proves the table's Location resolved to the right S3 prefix, the filtered
# count proves the catalog's column mapping is used.
_SPARK_JOB = """import sys

from pyspark.sql import SparkSession

table, out_uri, want_group = sys.argv[1], sys.argv[2], sys.argv[3]
spark = SparkSession.builder.appName("sim2real-xsvc-emr-glue").enableHiveSupport().getOrCreate()
total = spark.sql("SELECT COUNT(*) AS c FROM " + table).collect()[0]["c"]
filtered = spark.sql(
    "SELECT COUNT(*) AS c FROM " + table + " WHERE grp = '" + want_group + "'"
).collect()[0]["c"]
spark.sparkContext.parallelize(["%d,%d" % (total, filtered)], 1).saveAsTextFile(out_uri)
spark.stop()
"""


def _swallow(fn):
    """Run fn(), swallowing any exception. Teardown-only -- never an assertion."""
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


def _poll(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition", ctx=None):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _delete_with_retry(fn, attempts=60, delay=2, ctx=None):
    """Run an IAM delete, retrying DeleteConflict."""
    for i in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001
            if "DeleteConflict" not in str(exc) or i == attempts - 1 or _cleanup_spent(ctx):
                raise
            time.sleep(delay)


def _ensure_emr_roles(ctx):
    """Create the EMR service role and the EC2 instance profile, with Glue catalog reads granted.

    EMR_DefaultRole and EMR_EC2_DefaultRole do not exist in a fresh account, so the check makes its
    own.
    """
    iam = ctx.client("iam")
    svc_role = ctx.unique_name("sim2real-xsvc-emr-glue-svc-")
    ec2_role = ctx.unique_name("sim2real-xsvc-emr-glue-ec2-")
    glue_policy = "sim2real-xsvc-emr-glue-catalog-read"

    iam.create_role(
        RoleName=svc_role, AssumeRolePolicyDocument=_EMR_SERVICE_TRUST, Tags=_TAGS
    )
    ctx.on_cleanup(
        lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=svc_role), ctx=ctx)
    )
    iam.attach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY)
    )

    iam.create_role(RoleName=ec2_role, AssumeRolePolicyDocument=_EC2_TRUST, Tags=_TAGS)
    ctx.on_cleanup(
        lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=ec2_role), ctx=ctx)
    )
    iam.attach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY)
    )
    iam.put_role_policy(
        RoleName=ec2_role, PolicyName=glue_policy, PolicyDocument=_GLUE_READ_POLICY
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=ec2_role, PolicyName=glue_policy)
    )

    iam.create_instance_profile(InstanceProfileName=ec2_role, Tags=_TAGS)
    ctx.on_cleanup(
        lambda: _delete_with_retry(
            lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role), ctx=ctx
        )
    )
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=ec2_role, RoleName=ec2_role
        )
    )

    # No fixed IAM-propagation wait: _run_cluster's bounded retry covers a too-fresh role.
    return svc_role, ec2_role


def _pick_subnet(ctx):
    """The check's private subnet (see _private_network)."""
    return _private_network(ctx, INSTANCE_TYPE)[1]


def _make_bucket(ctx, s3):
    """Create the data/script/log bucket. Registered BEFORE the cluster so LIFO empties it AFTER
    the cluster is gone -- EMR keeps writing step logs into LogUri right up to termination."""
    bucket = ctx.unique_name("sim2real-xsvc-emr-glue-")

    def _cleanup() -> None:
        def _purge_and_delete() -> None:
            for page in s3.get_paginator("list_object_versions").paginate(
                Bucket=bucket
            ):
                victims = [
                    {"Key": o["Key"], "VersionId": o["VersionId"]}
                    for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
                ]
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
    return bucket


def _cluster_is_gone(exc):
    """True only for the error that means the cluster no longer exists."""
    code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
    return code in _CLUSTER_GONE_CODES or "is not valid" in str(exc)


def _terminate_and_await_teardown(emr, cluster_id, ctx=None):
    """Terminate the cluster and WAIT, so the IAM and Glue deletions registered earlier (and
    therefore running later, LIFO) do not race a cluster still assuming the service role."""
    _swallow(lambda: emr.terminate_job_flows(JobFlowIds=[cluster_id]))
    last = None
    deadline = _teardown_deadline(ctx, _CLEANUP_BUDGET_S)
    while time.monotonic() < deadline:
        try:
            state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"][
                "State"
            ]
        except Exception as exc:  # noqa: BLE001
            if _cluster_is_gone(exc):
                return
            last = exc
            time.sleep(2)
            continue
        if state in ("TERMINATED", "TERMINATED_WITH_ERRORS"):
            return
        last = state
        time.sleep(2)
    raise RuntimeError(f"EMR cluster {cluster_id} was not deleted: {last!r}")


def _run_cluster(emr, ctx, service_role, job_flow_role, **params):
    """RunJobFlow, retrying only the transient IAM-propagation / throttle errors, with teardown
    registered immediately after the id exists."""
    last = None
    resp = None
    deadline = time.monotonic() + _budget_s(ctx, 320)
    while True:
        try:
            resp = _run_job_flow_propagated(ctx, emr, 
                ServiceRole=service_role, JobFlowRole=job_flow_role, **params
            )
            break
        except Exception as exc:  # noqa: BLE001
            low = str(exc).lower()
            transient = (
                "throttl" in low
                or "rate exceeded" in low
                or "invalid instanceprofile" in low
                or "invalid ec2" in low
            )
            if not transient or time.monotonic() >= deadline:
                if transient and _budget_spent(ctx):
                    raise TimeoutError("RunJobFlow succeeding: the run budget ended first; not graded")
                raise
            last = exc
            time.sleep(2)
    if resp is None:
        raise AssertionError(f"RunJobFlow never succeeded: {last}")
    cluster_id = resp["JobFlowId"]
    ctx.on_cleanup(
        lambda: _terminate_and_await_teardown(emr, cluster_id, ctx=ctx)
    )
    return cluster_id


def _spark_result(s3, bucket, prefix):
    """(keys, payload) for a Spark text output under `prefix`, or (keys, None) with no part file."""
    keys = sorted(
        o["Key"]
        for page in s3.get_paginator("list_objects_v2").paginate(
            Bucket=bucket, Prefix=f"{prefix}/"
        )
        for o in page.get("Contents", [])
    )
    parts = [k for k in keys if "/part-" in k]
    if not parts:
        return keys, None
    return keys, s3.get_object(Bucket=bucket, Key=parts[0])[
        "Body"
    ].read().decode().strip()


def _head_status(s3, bucket, key):
    """HeadObject's error code, or the sentinel 'EXISTS' when the object is really there.

    Never returns a falsy value: an object that exists where the check expects a 404 is the
    strongest signal available, and a falsy sentinel would flatten it into a code mismatch.
    """
    try:
        s3.head_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code", "")
    return "EXISTS"


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c3",
    "cap:c5",
)
def run(ctx) -> None:
    """A Spark SQL step through the Glue Data Catalog fails on a table never registered in Glue and
    writes no output, while the same query on the registered table returns the CSV's exact counts.

    Reference: https://docs.aws.amazon.com/emr/latest/ReleaseGuide/emr-spark-glue.html
    """
    emr = ctx.client("emr")
    s3 = ctx.client("s3")
    glue = ctx.client("glue")

    service_role, job_flow_role = _ensure_emr_roles(ctx)
    subnet = _pick_subnet(ctx)
    bucket = _make_bucket(ctx, s3)

    # ---- the data, and the catalog entry that describes it -------------------------------------
    data_prefix = "data"
    rows = [f"{i},alpha" for i in range(_ALPHA_ROWS)] + [
        f"{_ALPHA_ROWS + i},beta" for i in range(_BETA_ROWS)
    ]
    s3.put_object(
        Bucket=bucket,
        Key=f"{data_prefix}/rows.csv",
        Body=("\n".join(rows) + "\n").encode("utf-8"),
    )

    script_key = "job/count_through_glue.py"
    s3.put_object(Bucket=bucket, Key=script_key, Body=_SPARK_JOB.encode("utf-8"))

    db_name = ctx.unique_name("sim2real_xsvc_emr_glue_db_").replace("-", "_")
    tbl_name = "rows"
    # A name deliberately never registered: the one broken thing.
    missing_tbl = "rows_not_in_the_catalog"

    glue.create_database(
        DatabaseInput={"Name": db_name, "Description": f"sim2real-xsvc {_SCENARIO}"}
    )
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    location = f"s3://{bucket}/{data_prefix}/"
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": tbl_name,
            "Description": f"sim2real-xsvc {_SCENARIO}",
            "TableType": "EXTERNAL_TABLE",
            "Parameters": {"classification": "csv", "EXTERNAL": "TRUE"},
            "StorageDescriptor": {
                "Columns": [
                    {"Name": "id", "Type": "int"},
                    {"Name": "grp", "Type": "string"},
                ],
                "Location": location,
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                    "Parameters": {"field.delim": ",", "serialization.format": ","},
                },
            },
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=tbl_name))

    # ---- the cluster, wired to Glue as its Hive metastore --------------------------------------
    good_prefix, bad_prefix = "out-registered", "out-missing"

    def _step(name, table, prefix):
        return {
            "Name": name,
            "ActionOnFailure": "CONTINUE",
            "HadoopJarStep": {
                "Jar": "command-runner.jar",
                "Args": [
                    "spark-submit",
                    "--deploy-mode",
                    "client",
                    f"s3://{bucket}/{script_key}",
                    f"{db_name}.{table}",
                    f"s3://{bucket}/{prefix}",
                    "alpha",
                ],
            },
        }

    cluster_id = _run_cluster(
        emr,
        ctx,
        service_role,
        job_flow_role,
        Name=ctx.unique_name("sim2real-xsvc-emr-glue-"),
        ReleaseLabel=RELEASE_LABEL,
        LogUri=f"s3://{bucket}/logs/",
        # Serial, so the control step provably completes before the failing one runs and neither
        # can starve the other of YARN containers on a single node.
        StepConcurrencyLevel=1,
        Instances={
            "InstanceCount": 1,
            "MasterInstanceType": INSTANCE_TYPE,
            "KeepJobFlowAliveWhenNoSteps": True,
            "TerminationProtected": False,
            "Ec2SubnetId": subnet,
        },
        Applications=[{"Name": "Spark"}, {"Name": "Hive"}],
        # THE wiring under test: Spark's Hive metastore client is the Glue Data Catalog.
        Configurations=[
            {
                "Classification": "spark-hive-site",
                "Properties": {
                    "hive.metastore.client.factory.class": "com.amazonaws.glue.catalog.metastore."
                    "AWSGlueDataCatalogHiveClientFactory"
                },
            }
        ],
        VisibleToAllUsers=True,
        Tags=_TAGS,
        Steps=[
            _step("sim2real-xsvc-glue-registered", tbl_name, good_prefix),
            _step("sim2real-xsvc-glue-missing", missing_tbl, bad_prefix),
        ],
    )

    submitted = [
        (s["Id"], s["Name"])
        for page in emr.get_paginator("list_steps").paginate(ClusterId=cluster_id)
        for s in page.get("Steps", [])
    ]
    assert len(submitted) == 2, (
        f"the cluster must hold exactly the two steps submitted at launch, got {submitted!r}"
    )
    by_name = {name: sid for sid, name in submitted}
    good_id = by_name["sim2real-xsvc-glue-registered"]
    bad_id = by_name["sim2real-xsvc-glue-missing"]

    def _state(step_id):
        return emr.describe_step(ClusterId=cluster_id, StepId=step_id)["Step"][
            "Status"
        ]["State"]

    finals = _poll(
        lambda: (_state(good_id), _state(bad_id)),
        lambda st: all(s in _STEP_TERMINAL for s in st),
        timeout_s=_budget_s(ctx, 1500),
        interval_s=2,
        ctx=ctx,
        description=f"both Glue-metastore steps on {cluster_id} reaching terminal states",
    )
    good_state, bad_state = finals

    # ---- the positive control first: the wiring works and the numbers are Spark's ---------------
    assert good_state == "COMPLETED", (
        f"the step querying the REGISTERED Glue table is the positive control and must reach "
        f"COMPLETED -- otherwise the other step's failure says nothing about the catalog -- got "
        f"{good_state!r} "
        f"({emr.describe_step(ClusterId=cluster_id, StepId=good_id)['Step']['Status'].get('FailureDetails')!r})"
    )
    keys, payload = _poll(
        lambda: _spark_result(s3, bucket, good_prefix),
        lambda kp: kp[1] is not None,
        timeout_s=_budget_s(ctx, 180),
        interval_s=2,
        ctx=ctx,
        description=f"Spark output under s3://{bucket}/{good_prefix}/",
    )
    assert any(k.endswith("/_SUCCESS") for k in keys), (
        f"Spark must commit its _SUCCESS marker for the control step; keys were {keys!r}"
    )
    assert payload == f"{_TOTAL_ROWS},{_ALPHA_ROWS}", (
        f"Spark must report the exact row counts of the CSV behind the Glue table: "
        f"{_TOTAL_ROWS} rows total and {_ALPHA_ROWS} in group 'alpha'. Got {payload!r}. A wrong "
        f"total means the StorageDescriptor Location was not honoured; a wrong filtered count "
        f"means the catalog's column mapping was not used."
    )

    # The read really went THROUGH the catalog, and the catalog still says what the check set.
    table = glue.get_table(DatabaseName=db_name, Name=tbl_name)["Table"]
    assert table["StorageDescriptor"]["Location"] == location, (
        f"Glue must still report the Location this check set, so the numbers above came through "
        f"the catalog rather than around it; expected {location!r}, got "
        f"{table['StorageDescriptor']['Location']!r}"
    )
    assert [c["Name"] for c in table["StorageDescriptor"]["Columns"]] == [
        "id",
        "grp",
    ], (
        f"the catalog's column list must be intact; got {table['StorageDescriptor']['Columns']!r}"
    )

    # ---- now the refusal: same query, same cluster, a table name Glue never had -----------------
    assert bad_state == "FAILED", (
        f"a Spark step resolving a table absent from the Glue catalog must FAIL, got "
        f"{bad_state!r} "
        f"({emr.describe_step(ClusterId=cluster_id, StepId=bad_id)['Step']['Status'].get('FailureDetails')!r})"
    )
    # And the catalog really has no such table, so the failure is the catalog miss and not
    # something else about the second step.
    absent, absent_message = _table_lookup_error(glue, db_name, missing_tbl)
    assert absent == "EntityNotFoundException", (
        f"Glue must confirm {db_name}.{missing_tbl} does not exist, so the step's failure is the "
        f"catalog miss; GetTable answered {absent!r}"
    )
    assert absent_message == "Entity Not Found", (
        f"GetTable on {db_name}.{missing_tbl} must carry Glue's exact not-found message; got "
        f"{absent_message!r}"
    )

    # ---- the effect is absent ------------------------------------------------------------------
    bad_marker = _head_status(s3, bucket, f"{bad_prefix}/_SUCCESS")
    assert bad_marker == "404", (
        f"the failing step must not commit Spark's _SUCCESS marker to "
        f"s3://{bucket}/{bad_prefix}/; HeadObject answered {bad_marker!r}"
    )
    bad_keys, bad_payload = _spark_result(s3, bucket, bad_prefix)
    assert bad_payload is None and bad_keys == [], (
        f"the failing step must write nothing at all under s3://{bucket}/{bad_prefix}/ -- a "
        f"backend that fell back to reading the S3 prefix directly, ignoring the catalog, would "
        f"produce a count here; found keys {bad_keys!r} payload {bad_payload!r}"
    )


def _table_lookup_error(glue, database, table):
    """The (code, message) GetTable raises for `table`, or ('EXISTS', None) when it is really there.

    Never returns a falsy value: a table that exists where the check requires absence is the whole
    premise collapsing, and a falsy sentinel would read as a code-naming difference.
    """
    try:
        glue.get_table(DatabaseName=database, Name=table)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message")
    return "EXISTS", None


def _run_job_flow_propagated(ctx, emr, **params):
    """RunJobFlow, retrying every 2 s while IAM has not yet propagated a new instance profile to EMR
    ("Failed to authorize instance profile"), to min(180 s, the check's time left); raises the rest."""
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
