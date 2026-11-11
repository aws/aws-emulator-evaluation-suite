"""glue-job-rejects-a-type-violating-source-row-and-writes-no-output-or-partition."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "glue-job-rejects-a-type-violating-source-row-and-writes-no-output-or-partition"
GROUP = 'jobs'
SERVICES = ["glue"]

# Two Glue 4.0 G.1X x2 Spark runs of the SAME job, sequentially: the control and the arm with
# one changed cell. Measured startup-to-terminal is 70-130 s a run, and the role Glue must
# assume is created by this check, so the bounded propagation retry can cost another run. This
# deadline is a hard cap shared by every wait below.
_TOTAL_DEADLINE_S = 1500.0

_DTS = ("2026-04-01", "2026-04-02", "2026-04-03")
_ROWS = 120
#: The row whose `amount` cell is replaced in the negative arm. Everything else is identical.
_BAD_ROW = 7
_BAD_CELL = "not-a-number"

_TEXT_INPUT = "org.apache.hadoop.mapred.TextInputFormat"
_TEXT_OUTPUT = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"
_LAZY_SERDE = "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe"
_PARQUET_INPUT = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
_PARQUET_OUTPUT = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"
_PARQUET_SERDE = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"


def _build_inputs() -> tuple[bytes, bytes]:
    """The control CSV and the arm CSV, which differ in exactly one cell."""
    good, bad = [], []
    for i in range(1, _ROWS + 1):
        amount = (i % 17) + 0.5
        dt = _DTS[i % 3]
        good.append(f"{i},{amount},{dt}")
        bad.append(f"{i},{_BAD_CELL},{dt}" if i == _BAD_ROW else f"{i},{amount},{dt}")
    header = "order_id,amount,dt\n"
    return (header + "\n".join(good) + "\n").encode(), \
           (header + "\n".join(bad) + "\n").encode()


_GOOD_CSV, _BAD_CSV = _build_inputs()

# One script, run twice. The catalog source table declares every column as `string` -- which is
# what a raw CSV landing table honestly is -- so the numeric conversion happens in Spark, under
# ANSI semantics, and a cell that is not a number is a runtime failure rather than a silent
# NULL. Nothing about the two runs differs except the object the source table points at.
_SCRIPT = b"""import sys
from awsglue.context import GlueContext
from awsglue.dynamicframe import DynamicFrame
from awsglue.job import Job
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext
from pyspark.sql.functions import col

a = getResolvedOptions(sys.argv, ['JOB_NAME', 'DB', 'SRC', 'TGT', 'OUTPUT'])
sc = SparkContext.getOrCreate()
gc = GlueContext(sc)
gc.spark_session.conf.set('spark.sql.ansi.enabled', 'true')
job = Job(gc)
job.init(a['JOB_NAME'], a)

src = gc.create_dynamic_frame.from_catalog(database=a['DB'],
                                           table_name=a['SRC']).toDF()
out = src.select(col('order_id').cast('int').alias('order_id'),
                 (col('amount').cast('double') * 2).alias('amount'),
                 col('dt').cast('string').alias('dt'))

sink = gc.getSink(path=a['OUTPUT'], connection_type='s3',
                  updateBehavior='UPDATE_IN_DATABASE', partitionKeys=['dt'],
                  compression='snappy', enableUpdateCatalog=True,
                  transformation_ctx='sink')
sink.setCatalogInfo(catalogDatabase=a['DB'], catalogTableName=a['TGT'])
sink.setFormat('glueparquet')
sink.writeFrame(DynamicFrame.fromDF(out, gc, 'out'))
job.commit()
"""


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """One unconvertible source cell fails the Glue job run, leaving no output object or partition.
    A control run over clean input succeeds with three partitions, intact after the failed run.

    Reference: https://docs.aws.amazon.com/glue/latest/dg/aws-glue-api-jobs-runs.html
    """
    deadline = time.monotonic() + _budget_s(ctx, _TOTAL_DEADLINE_S)
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = ctx.unique_name("sim2real-behav-gluebad-").lower()
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket,
                          Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_object(Bucket=bucket, Key="scripts/etl.py", Body=_SCRIPT)
    s3.put_object(Bucket=bucket, Key="good/orders.csv", Body=_GOOD_CSV)
    s3.put_object(Bucket=bucket, Key="bad/orders.csv", Body=_BAD_CSV)

    database = ctx.unique_name("sim2real_behav_gluebad_")
    glue.create_database(DatabaseInput={"Name": database,
                                       "Description": f"SimParity {CHECK}"})
    ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_database(Name=database),
                                         f"glue database {database}"))

    for name, prefix in (("src_good_csv", "good/"), ("src_bad_csv", "bad/")):
        _create_source_table(ctx, glue, database, name, f"s3://{bucket}/{prefix}")
    for name, prefix in (("tgt_good_parquet", "out-good/"), ("tgt_bad_parquet", "out-bad/")):
        _create_target_table(ctx, glue, database, name, f"s3://{bucket}/{prefix}")

    for table in ("tgt_good_parquet", "tgt_bad_parquet"):
        existing = _partition_values(glue, database, table)
        assert existing == [], (
            f"{table!r} already held partitions {existing!r} before any run, so neither an "
            f"appearance nor an absence afterwards would be evidence"
        )

    role_arn = _create_glue_role(ctx, iam, bucket)

    job = ctx.unique_name("sim2real-behav-gluebad-")
    glue.create_job(
        Name=job, Role=role_arn,
        Command={"Name": "glueetl", "PythonVersion": "3",
                 "ScriptLocation": f"s3://{bucket}/scripts/etl.py"},
        GlueVersion="4.0", WorkerType="G.1X", NumberOfWorkers=2,
        ExecutionProperty={"MaxConcurrentRuns": 5},
        DefaultArguments={"--TempDir": f"s3://{bucket}/tmp/"},
        Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_job(JobName=job),
                                         f"glue job {job}"))

    # --- positive control: the same job over clean bytes ----------------------------------
    control = _run_job_to_terminal(glue, job, {
        "--DB": database, "--SRC": "src_good_csv", "--TGT": "tgt_good_parquet",
        "--OUTPUT": f"s3://{bucket}/out-good/"}, deadline=deadline)
    if (control.get("JobRunState") not in ("SUCCEEDED", "FAILED", "STOPPED", "ERROR", "TIMEOUT")
            or "assume role permissions" in (control.get("ErrorMessage") or "")) and _budget_spent(ctx):
        raise TimeoutError("the control job run reaching a terminal state: the run budget ended first; not graded")
    assert control.get("JobRunState") == "SUCCEEDED", (
        f"the control run over clean bytes ended {control.get('JobRunState')!r}: "
        f"{control.get('ErrorMessage')!r}; nothing the negative arm shows would be "
        f"attributable to the changed cell"
    )
    control_keys = _list_keys(s3, bucket, "out-good/")
    assert control_keys, "the control run wrote no object under 'out-good/'"
    control_partitions = _partition_values(glue, database, "tgt_good_parquet")
    assert control_partitions == [[dt] for dt in _DTS], (
        f"the control run registered partitions {control_partitions!r}, expected one per dt "
        f"value {[[dt] for dt in _DTS]!r}"
    )

    # --- the arm: one cell of one row is not a number --------------------------------------
    arm = _run_job_to_terminal(glue, job, {
        "--DB": database, "--SRC": "src_bad_csv", "--TGT": "tgt_bad_parquet",
        "--OUTPUT": f"s3://{bucket}/out-bad/"}, deadline=deadline)
    if (arm.get("JobRunState") not in ("SUCCEEDED", "FAILED", "STOPPED", "ERROR", "TIMEOUT")
            or "assume role permissions" in (arm.get("ErrorMessage") or "")) and _budget_spent(ctx):
        raise TimeoutError("the arm job run reaching a terminal state: the run budget ended first; not graded")
    assert arm.get("JobRunState") == "FAILED", (
        f"the run over a source whose row {_BAD_ROW} carries amount={_BAD_CELL!r} ended "
        f"{arm.get('JobRunState')!r}, expected 'FAILED'; error was "
        f"{arm.get('ErrorMessage')!r}"
    )
    message = arm.get("ErrorMessage") or ""
    assert _BAD_CELL in message, (
        f"the failed run's ErrorMessage does not name the value that broke it: {message!r}"
    )

    # --- the effect is absent, in both systems --------------------------------------------
    arm_keys = _list_keys(s3, bucket, "out-bad/")
    assert arm_keys == [], (
        f"the failed run left objects under 'out-bad/': {arm_keys!r}"
    )
    arm_partitions = _partition_values(glue, database, "tgt_bad_parquet")
    assert arm_partitions == [], (
        f"the failed run registered catalog partitions {arm_partitions!r} on "
        f"'tgt_bad_parquet'; a run that produced no data must register no partition"
    )
    arm_table = glue.get_table(DatabaseName=database, Name="tgt_bad_parquet")["Table"]
    assert arm_table["StorageDescriptor"]["Location"].rstrip("/") == \
        f"s3://{bucket}/out-bad", (
        f"the failed run rewrote the target's location to "
        f"{arm_table['StorageDescriptor']['Location']!r}"
    )

    # --- and the control's result is untouched by the failure ------------------------------
    assert _list_keys(s3, bucket, "out-good/") == control_keys, (
        f"the failed run changed the control run's objects; 'out-good/' held "
        f"{control_keys!r} and now holds {_list_keys(s3, bucket, 'out-good/')!r}"
    )
    assert _partition_values(glue, database, "tgt_good_parquet") == control_partitions, (
        f"the failed run changed the control table's partitions; they were "
        f"{control_partitions!r} and are now "
        f"{_partition_values(glue, database, 'tgt_good_parquet')!r}"
    )
    assert _get_object(s3, bucket, "bad/orders.csv") == _BAD_CSV, (
        "the source object was modified by the failed run; it must be read-only to the job"
    )


# ===== helpers =====

def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _create_source_table(ctx, glue, database: str, name: str, location: str) -> None:
    """A CSV landing table whose every column is a string: the conversion is the job's."""
    glue.create_table(DatabaseName=database, TableInput={
        "Name": name,
        "TableType": "EXTERNAL_TABLE",
        "Parameters": {"classification": "csv", "skip.header.line.count": "1"},
        "StorageDescriptor": {
            "Columns": [{"Name": "order_id", "Type": "string"},
                        {"Name": "amount", "Type": "string"},
                        {"Name": "dt", "Type": "string"}],
            "Location": location,
            "InputFormat": _TEXT_INPUT,
            "OutputFormat": _TEXT_OUTPUT,
            "SerdeInfo": {"SerializationLibrary": _LAZY_SERDE,
                          "Parameters": {"field.delim": ","}}}})
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: glue.delete_table(DatabaseName=database, Name=name),
        f"glue table {database}.{name}"))


def _create_target_table(ctx, glue, database: str, name: str, location: str) -> None:
    """A partitioned Parquet table the job may add partitions to but did not define."""
    glue.create_table(DatabaseName=database, TableInput={
        "Name": name,
        "TableType": "EXTERNAL_TABLE",
        "Parameters": {"classification": "parquet"},
        "PartitionKeys": [{"Name": "dt", "Type": "string"}],
        "StorageDescriptor": {
            "Columns": [{"Name": "order_id", "Type": "int"},
                        {"Name": "amount", "Type": "double"}],
            "Location": location,
            "InputFormat": _PARQUET_INPUT,
            "OutputFormat": _PARQUET_OUTPUT,
            "SerdeInfo": {"SerializationLibrary": _PARQUET_SERDE}}})
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: glue.delete_table(DatabaseName=database, Name=name),
        f"glue table {database}.{name}"))


def _create_bucket(ctx, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})


def _create_glue_role(ctx, iam, bucket: str) -> str:
    """Create a role Glue can assume, with read and write on exactly one bucket."""
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow",
                       "Principal": {"Service": "glue.amazonaws.com"},
                       "Action": "sts:AssumeRole"}]})
    role = ctx.unique_name("sim2real-behav-gluerole-")
    arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=trust,
                          Description=f"SimParity {CHECK}",
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: iam.delete_role(RoleName=role),
                                         f"iam role {role}"))
    managed = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role, PolicyArn=managed)
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: iam.detach_role_policy(RoleName=role, PolicyArn=managed),
        f"detach {managed} from {role}"))
    iam.put_role_policy(RoleName=role, PolicyName="sim2real-s3", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow",
                       "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                       "Resource": f"arn:aws:s3:::{bucket}/*"},
                      {"Effect": "Allow",
                       "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
                       "Resource": f"arn:aws:s3:::{bucket}"}]}))
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: iam.delete_role_policy(RoleName=role, PolicyName="sim2real-s3"),
        f"inline policy on {role}"))
    # IAM exposes no condition to poll for a role becoming assumable by a service; the
    # bounded retry in _run_job_to_terminal covers its propagation.
    return arn


def _run_job_to_terminal(glue, job: str, arguments: dict, *, deadline: float) -> dict:
    """Start the job and poll to a terminal state, retrying the IAM-propagation failure.

    Glue reports "Role ... should be given assume role permissions for Glue Service" as a
    FAILED job *run* about 5 s in, not as a StartJobRun error, and no API reports that the
    role has become assumable -- so the bounded retry has to be on the terminal run state.
    """
    from botocore.exceptions import ClientError

    record: dict = {}
    while time.monotonic() < deadline:
        try:
            run_id = glue.start_job_run(JobName=job, Arguments=arguments)["JobRunId"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ConcurrentRunsExceededException":
                raise
            time.sleep(2)
            continue
        while time.monotonic() < deadline:
            record = glue.get_job_run(JobName=job, RunId=run_id)["JobRun"]
            if record["JobRunState"] in ("SUCCEEDED", "FAILED", "STOPPED", "ERROR",
                                         "TIMEOUT"):
                break
            time.sleep(1)
        if record.get("JobRunState") != "FAILED":
            return record
        if "assume role permissions" not in (record.get("ErrorMessage") or ""):
            return record
        time.sleep(2)
    return record


def _partition_values(glue, database: str, table: str) -> list:
    parts = []
    for page in glue.get_paginator("get_partitions").paginate(DatabaseName=database,
                                                              TableName=table):
        parts.extend(page.get("Partitions", []))
    return sorted(p["Values"] for p in parts)


def _get_object(s3, bucket: str, key: str):
    from botocore.exceptions import ClientError
    try:
        return s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    except ClientError as err:
        if err.response["Error"]["Code"] == "NoSuchKey":
            return None
        raise


def _list_keys(s3, bucket: str, prefix: str) -> list:
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return sorted(keys)


def _retry_delete(fn: Callable[[], Any], label: str, *, timeout_s: float = 120.0) -> None:
    """Delete with a bounded retry, because ctx.on_cleanup SWALLOWS teardown exceptions:
    a throttled or dependency-blocked delete would leak silently while the check passes."""
    from botocore.exceptions import ClientError

    gone = ("EntityNotFoundException", "NoSuchEntity", "NoSuchBucket",
            "ResourceNotFoundException", "404")
    transient = ("ThrottlingException", "Throttling", "TooManyRequestsException",
                 "OperationTimeoutException", "ConcurrentModificationException",
                 "DeleteConflict", "InvalidInputException", "RequestLimitExceeded")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in gone:
                return
            if code not in transient or time.monotonic() >= deadline:
                raise RuntimeError(f"{label}: {code}: {err}") from err
            time.sleep(3)
        except Exception as exc:  # noqa: BLE001 - re-raised
            raise RuntimeError(f"{label}: {type(exc).__name__}: {exc}") from exc


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    from botocore.exceptions import ClientError

    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objects = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                       for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objects:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchBucket":
            return
        raise
    _retry_delete(lambda: s3.delete_bucket(Bucket=bucket), f"s3 bucket {bucket}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
