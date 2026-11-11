"""glue-job-runs-add-catalog-partitions-incrementally-and-re-registering-one-creates-no-duplicate."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = (
    "glue-job-runs-add-catalog-partitions-incrementally-and-re-registering-one-creates-no-duplicate"
)
GROUP = 'jobs'
SERVICES = ["glue"]

# Three sequential Glue 4.0 G.1X x2 Spark runs of the same job. Measured startup-to-terminal is
# 70-130 s a run, and the role Glue must assume is created by this check, so the bounded
# propagation retry can cost another run. This deadline is a hard cap shared by every wait
# below, so the check can never outlive its wrapper and manufacture a timeout.
_TOTAL_DEADLINE_S = 1700.0

#: (dt value -> rows) per source prefix. The counts differ per prefix so the running total the
#: job reports back after each commit is unambiguous about which runs contributed to it.
_FIRST = {"2026-05-01": 30, "2026-05-02": 30}
_SECOND = {"2026-05-03": 40}
_FIRST_ROWS = sum(_FIRST.values())
_SECOND_ROWS = sum(_SECOND.values())

_TEXT_INPUT = "org.apache.hadoop.mapred.TextInputFormat"
_TEXT_OUTPUT = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"
_LAZY_SERDE = "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe"
_PARQUET_INPUT = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
_PARQUET_OUTPUT = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"
_PARQUET_SERDE = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"


def _csv(groups: dict) -> bytes:
    lines = []
    i = 0
    for dt, rows in sorted(groups.items()):
        for _ in range(rows):
            i += 1
            lines.append(f"{i},{(i % 23) + 0.5},{dt}")
    return ("order_id,amount,dt\n" + "\n".join(lines) + "\n").encode()


_FIRST_CSV = _csv(_FIRST)
_SECOND_CSV = _csv(_SECOND)

# One script, run three times against the same target table. After committing, it re-reads the
# WHOLE target path and reports the running row total, so the marker is a fact about the
# accumulated Parquet rather than about the run's own input.
_SCRIPT = b"""import sys
import boto3
from awsglue.context import GlueContext
from awsglue.dynamicframe import DynamicFrame
from awsglue.job import Job
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext
from pyspark.sql.functions import col

a = getResolvedOptions(sys.argv, ['JOB_NAME', 'DB', 'SRC', 'TGT', 'OUTPUT', 'MARKER'])
sc = SparkContext.getOrCreate()
gc = GlueContext(sc)
job = Job(gc)
job.init(a['JOB_NAME'], a)

src = gc.create_dynamic_frame.from_catalog(database=a['DB'],
                                          table_name=a['SRC']).toDF()
src_rows = src.count()
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

back = gc.spark_session.read.parquet(a['OUTPUT'])
bucket, key = a['MARKER'][len('s3://'):].split('/', 1)
boto3.client('s3').put_object(Bucket=bucket, Key=key,
                              Body=('%d|%d' % (src_rows, back.count())).encode())
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Successive job runs add only the partitions they wrote, leaving earlier ones unchanged, and
    re-running a source adds data under the existing partition but no new partition: a catalog
    partition is identified by its values, not by the write that produced it."""
    left = ctx.time_left()
    deadline = time.monotonic() + (_TOTAL_DEADLINE_S if left is None else min(_TOTAL_DEADLINE_S, left))
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = ctx.unique_name("sim2real-behav-glueinc-").lower()
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket,
                          Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_object(Bucket=bucket, Key="scripts/etl.py", Body=_SCRIPT)
    s3.put_object(Bucket=bucket, Key="first/orders.csv", Body=_FIRST_CSV)
    s3.put_object(Bucket=bucket, Key="second/orders.csv", Body=_SECOND_CSV)

    database = ctx.unique_name("sim2real_behav_glueinc_")
    glue.create_database(DatabaseInput={"Name": database,
                                       "Description": f"SimParity {CHECK}"})
    ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_database(Name=database),
                                         f"glue database {database}"))

    for name, prefix in (("src_first_csv", "first/"), ("src_second_csv", "second/")):
        _create_source_table(ctx, glue, database, name, f"s3://{bucket}/{prefix}")

    target_location = f"s3://{bucket}/target/"
    target = "tgt_orders_parquet"
    _create_target_table(ctx, glue, database, target, target_location)

    before = _partition_values(glue, database, target)
    assert before == [], (
        f"the target table already held partitions {before!r} before any run, so a partition "
        f"found afterwards would not be evidence a run created it"
    )

    role_arn = _create_glue_role(ctx, iam, bucket)

    job = ctx.unique_name("sim2real-behav-glueinc-")
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

    def _go(source: str, marker: str) -> dict:
        record = _run_job_to_terminal(glue, job, {
            "--DB": database, "--SRC": source, "--TGT": target,
            "--OUTPUT": target_location,
            "--MARKER": f"s3://{bucket}/marker/{marker}.txt"}, deadline=deadline)
        assert record.get("JobRunState") == "SUCCEEDED", (
            f"the run over {source!r} ended {record.get('JobRunState')!r}: "
            f"{record.get('ErrorMessage')!r}"
        )
        return record

    # --- run 1: two dt values ---------------------------------------------------------------
    _go("src_first_csv", "first")
    after_first = _partitions_by_value(glue, database, target)
    assert sorted(after_first) == sorted(_FIRST), (
        f"run 1 wrote {sorted(_FIRST)!r} and the table holds partitions "
        f"{sorted(after_first)!r}"
    )
    first_keys = {dt: _list_keys(s3, bucket, f"target/dt={dt}/") for dt in _FIRST}
    for dt, keys in first_keys.items():
        assert keys, f"run 1 registered partition {dt!r} but its prefix holds no object"
    assert _get_object(s3, bucket, "marker/first.txt") == \
        ("%d|%d" % (_FIRST_ROWS, _FIRST_ROWS)).encode(), (
        f"run 1 reported {_get_object(s3, bucket, 'marker/first.txt')!r}, expected "
        f"{('%d|%d' % (_FIRST_ROWS, _FIRST_ROWS)).encode()!r} (src_rows|rows in target)"
    )

    # --- run 2: one further, disjoint dt value ----------------------------------------------
    _go("src_second_csv", "second")
    after_second = _partitions_by_value(glue, database, target)
    assert sorted(after_second) == sorted({**_FIRST, **_SECOND}), (
        f"run 2 wrote {sorted(_SECOND)!r} and the table now holds "
        f"{sorted(after_second)!r}; it should have GAINED exactly those"
    )
    for dt in _FIRST:
        assert after_second[dt] == after_first[dt], (
            f"run 2 moved partition {dt!r} from {after_first[dt]!r} to "
            f"{after_second[dt]!r}; it wrote nothing under that value"
        )
        assert _list_keys(s3, bucket, f"target/dt={dt}/") == first_keys[dt], (
            f"run 2 changed the objects under partition {dt!r}: they were "
            f"{first_keys[dt]!r} and are now "
            f"{_list_keys(s3, bucket, f'target/dt={dt}/')!r}"
        )
    second_dt = next(iter(_SECOND))
    second_keys = _list_keys(s3, bucket, f"target/dt={second_dt}/")
    assert second_keys, f"run 2 registered partition {second_dt!r} but wrote no object there"
    running = _FIRST_ROWS + _SECOND_ROWS
    assert _get_object(s3, bucket, "marker/second.txt") == \
        ("%d|%d" % (_SECOND_ROWS, running)).encode(), (
        f"run 2 reported {_get_object(s3, bucket, 'marker/second.txt')!r}, expected "
        f"{('%d|%d' % (_SECOND_ROWS, running)).encode()!r} (src_rows|rows in target)"
    )

    # --- run 3: the same source again -------------------------------------------------------
    _go("src_second_csv", "again")
    after_third = _partitions_by_value(glue, database, target)
    assert after_third == after_second, (
        f"re-running the same source changed the partition set from {after_second!r} to "
        f"{after_third!r}; a partition is identified by its values, so a repeat write must "
        f"register no new partition and relocate none"
    )
    again_keys = _list_keys(s3, bucket, f"target/dt={second_dt}/")
    assert set(second_keys) < set(again_keys), (
        f"the repeat run did not append under partition {second_dt!r}: the prefix held "
        f"{second_keys!r} and now holds {again_keys!r}"
    )
    assert _get_object(s3, bucket, "marker/again.txt") == \
        ("%d|%d" % (_SECOND_ROWS, running + _SECOND_ROWS)).encode(), (
        f"run 3 reported {_get_object(s3, bucket, 'marker/again.txt')!r}, expected "
        f"{('%d|%d' % (_SECOND_ROWS, running + _SECOND_ROWS)).encode()!r}; the repeat must "
        f"ADD its rows to the target rather than replace them"
    )

    # --- the definition this check registered survived all three runs -----------------------
    table = glue.get_table(DatabaseName=database, Name=target)["Table"]
    assert [k["Name"] for k in table["PartitionKeys"]] == ["dt"], (
        f"the runs rewrote the partition keys to {table['PartitionKeys']!r}"
    )
    assert table["StorageDescriptor"]["Location"].rstrip("/") == \
        target_location.rstrip("/"), (
        f"the runs relocated the table to {table['StorageDescriptor']['Location']!r}, "
        f"expected {target_location!r}"
    )


# ===== helpers =====

def _create_source_table(ctx, glue, database: str, name: str, location: str) -> None:
    glue.create_table(DatabaseName=database, TableInput={
        "Name": name,
        "TableType": "EXTERNAL_TABLE",
        "Parameters": {"classification": "csv", "skip.header.line.count": "1"},
        "StorageDescriptor": {
            "Columns": [{"Name": "order_id", "Type": "int"},
                        {"Name": "amount", "Type": "double"},
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
    # bounded retry in _run_job_to_terminal waits out that propagation.
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
            time.sleep(5)
            continue
        while time.monotonic() < deadline:
            record = glue.get_job_run(JobName=job, RunId=run_id)["JobRun"]
            if record["JobRunState"] in ("SUCCEEDED", "FAILED", "STOPPED", "ERROR",
                                         "TIMEOUT"):
                break
            time.sleep(5)
        if record.get("JobRunState") != "FAILED":
            return record
        if "assume role permissions" not in (record.get("ErrorMessage") or ""):
            return record
        time.sleep(2)
    return record


def _list_partitions(glue, database: str, table: str) -> list:
    parts = []
    for page in glue.get_paginator("get_partitions").paginate(DatabaseName=database,
                                                              TableName=table):
        parts.extend(page.get("Partitions", []))
    return parts


def _partition_values(glue, database: str, table: str) -> list:
    return sorted(p["Values"] for p in _list_partitions(glue, database, table))


def _partitions_by_value(glue, database: str, table: str) -> dict:
    """Single-key partitions as {value: location}. Asserts the arity rather than assuming it."""
    out = {}
    for part in _list_partitions(glue, database, table):
        assert len(part["Values"]) == 1, (
            f"partition {part['Values']!r} has arity {len(part['Values'])}; the table "
            f"declares one partition key"
        )
        out[part["Values"][0]] = part["StorageDescriptor"]["Location"].rstrip("/")
    return out


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
