"""glue-job-reads-its-source-through-the-catalog-and-writes-partitions-into-a-registered-table."""
from __future__ import annotations

import json
import time
from typing import Any, Callable
from urllib.parse import urlparse

from behavioral_harness import tags

CHECK = (
    "glue-job-reads-its-source-through-the-catalog-and-writes-partitions-into-a-registered-table"
)
GROUP = 'jobs'
SERVICES = ["glue"]

# Per-check time budget shared by every wait; elapsed time is never asserted.
_SUITE_BUDGET_S = 1800.0

_DTS = ("2026-01-01", "2026-01-02", "2026-01-03")
_ROWS = 300

_TEXT_INPUT = "org.apache.hadoop.mapred.TextInputFormat"
_TEXT_OUTPUT = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"
_LAZY_SERDE = "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe"
_PARQUET_INPUT = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
_PARQUET_OUTPUT = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"
_PARQUET_SERDE = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"


def _build_input() -> tuple[bytes, float]:
    """The source CSV and its doubled amount total; every amount ends in .5, so the doubled
    sum is exactly representable and needs no tolerance."""
    lines = []
    doubled = 0.0
    for i in range(1, _ROWS + 1):
        amount = (i % 41) + 0.5
        lines.append(f"{i},{amount},{_DTS[i % 3]}")
        doubled += amount * 2
    csv = ("order_id,amount,dt\n" + "\n".join(lines) + "\n").encode()
    return csv, doubled


_CSV, _DOUBLED_TOTAL = _build_input()

# The job declares no schema or input format (columns and the header line come from the catalog
# table), registers partitions via getSink(enableUpdateCatalog=True), and computes the marker by
# re-reading the Parquet the sink wrote.
_SCRIPT = b"""import sys
import boto3
from awsglue.context import GlueContext
from awsglue.dynamicframe import DynamicFrame
from awsglue.job import Job
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext
from pyspark.sql.functions import col
from pyspark.sql.functions import sum as sum_

a = getResolvedOptions(sys.argv, ['JOB_NAME', 'DB', 'SRC', 'TGT', 'OUTPUT', 'MARKER'])
sc = SparkContext.getOrCreate()
gc = GlueContext(sc)
job = Job(gc)
job.init(a['JOB_NAME'], a)

dyf = gc.create_dynamic_frame.from_catalog(database=a['DB'], table_name=a['SRC'])
src = dyf.toDF()
src_rows = src.count()
src_cols = ','.join(sorted(src.columns))

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
back_rows = back.count()
total = back.select(sum_(col('amount'))).collect()[0][0]
back_cols = ','.join(sorted(back.columns))
bucket, key = a['MARKER'][len('s3://'):].split('/', 1)
boto3.client('s3').put_object(
    Bucket=bucket, Key=key,
    Body=('%d|%s|%d|%.1f|%s' % (src_rows, src_cols, back_rows, total,
                                back_cols)).encode())
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A Spark job reads its source schema through the Data Catalog, writes Parquet under a Hive
    dt= layout, and registers one partition per dt in a table it did not define, leaving that
    table's definition intact; the deleted job and table are then refused.
    """
    left = ctx.time_left()
    deadline = time.monotonic() + (_SUITE_BUDGET_S if left is None else min(_SUITE_BUDGET_S, left))
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = ctx.unique_name("sim2real-behav-gluecat-").lower()
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket,
                          Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_object(Bucket=bucket, Key="scripts/etl.py", Body=_SCRIPT)
    s3.put_object(Bucket=bucket, Key="source/orders.csv", Body=_CSV)

    database = ctx.unique_name("sim2real_behav_gluecat_")
    glue.create_database(DatabaseInput={"Name": database,
                                        "Description": f"SimParity {CHECK}"})
    ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_database(Name=database),
                                         f"glue database {database}"))

    source_location = f"s3://{bucket}/source/"
    target_location = f"s3://{bucket}/target/"
    src_table = "src_orders_csv"
    tgt_table = "tgt_orders_parquet"

    # The catalog is the only place the source schema exists: the job declares none.
    glue.create_table(DatabaseName=database, TableInput={
        "Name": src_table,
        "TableType": "EXTERNAL_TABLE",
        "Parameters": {"classification": "csv", "skip.header.line.count": "1"},
        "StorageDescriptor": {
            "Columns": [{"Name": "order_id", "Type": "int"},
                        {"Name": "amount", "Type": "double"},
                        {"Name": "dt", "Type": "string"}],
            "Location": source_location,
            "InputFormat": _TEXT_INPUT,
            "OutputFormat": _TEXT_OUTPUT,
            "SerdeInfo": {"SerializationLibrary": _LAZY_SERDE,
                          "Parameters": {"field.delim": ","}}}})
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: glue.delete_table(DatabaseName=database, Name=src_table),
        f"glue table {database}.{src_table}"))

    # The target is declared HERE, partition key included, and the job is given only its name.
    glue.create_table(DatabaseName=database, TableInput={
        "Name": tgt_table,
        "TableType": "EXTERNAL_TABLE",
        "Parameters": {"classification": "parquet"},
        "PartitionKeys": [{"Name": "dt", "Type": "string"}],
        "StorageDescriptor": {
            "Columns": [{"Name": "order_id", "Type": "int"},
                        {"Name": "amount", "Type": "double"}],
            "Location": target_location,
            "InputFormat": _PARQUET_INPUT,
            "OutputFormat": _PARQUET_OUTPUT,
            "SerdeInfo": {"SerializationLibrary": _PARQUET_SERDE}}})
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: glue.delete_table(DatabaseName=database, Name=tgt_table),
        f"glue table {database}.{tgt_table}"))

    before = _list_partition_values(glue, database, tgt_table)
    assert before == [], (
        f"the target table already had partitions {before!r} before the run, so a partition "
        f"found afterwards would not be evidence the job created it"
    )

    role_arn = _create_glue_role(ctx, iam, bucket)

    job = ctx.unique_name("sim2real-behav-gluecat-")
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

    marker_key = "marker/reread.txt"
    record = _run_job_to_terminal(glue, job, {
        "--DB": database,
        "--SRC": src_table,
        "--TGT": tgt_table,
        "--OUTPUT": target_location,
        "--MARKER": f"s3://{bucket}/{marker_key}"}, deadline=deadline)

    assert record.get("JobRunState") == "SUCCEEDED", (
        f"job run ended {record.get('JobRunState')!r}: {record.get('ErrorMessage')!r}"
    )

    written = _list_keys(s3, bucket, "target/")
    part_keys = [k for k in written if "/" in k[len("target/"):]]
    assert part_keys, (
        f"no object under a partition directory below 'target/' after a SUCCEEDED run; the "
        f"prefix holds {written!r}"
    )
    for dt in _DTS:
        under = [k for k in part_keys if k.startswith(f"target/dt={dt}/")]
        assert under, (
            f"nothing written under the Hive partition directory 'target/dt={dt}/'; the "
            f"prefix holds {part_keys!r}"
        )
    bodies = {k: _get_object(s3, bucket, k) for k in part_keys}
    magic = {k: (b[:4], b[-4:]) for k, b in bodies.items()}
    assert all(head == b"PAR1" and tail == b"PAR1" for head, tail in magic.values()), (
        f"an object under 'target/' is not a Parquet file; head/tail pairs were {magic!r}"
    )
    assert not any(b.startswith(b"order_id,") for b in bodies.values()), (
        f"an object under 'target/' still looks like the source CSV: "
        f"{next(iter(bodies.values()))[:40]!r}"
    )
    assert _get_object(s3, bucket, "source/orders.csv") == _CSV, (
        "the source object was modified by the run; it must be read-only to the job"
    )

    # The target had zero partitions before the run, so every partition here came from the sink.
    partitions = _list_partitions(glue, database, tgt_table)
    values = sorted(p["Values"] for p in partitions)
    assert values == [[dt] for dt in _DTS], (
        f"the job registered partitions {values!r}, expected one per dt value "
        f"{[[dt] for dt in _DTS]!r}"
    )
    for part in partitions:
        dt = part["Values"][0]
        location = part["StorageDescriptor"]["Location"]
        expected = f"{target_location}dt={dt}"
        assert location.rstrip("/") == expected.rstrip("/"), (
            f"partition {dt!r} points at {location!r}, expected {expected!r}"
        )
        parsed = urlparse(location)
        prefix = parsed.path.lstrip("/").rstrip("/") + "/"
        assert parsed.netloc == bucket, (
            f"partition {dt!r} points at bucket {parsed.netloc!r}, expected {bucket!r}"
        )
        assert any(k.startswith(prefix) for k in part_keys), (
            f"partition {dt!r} points at {prefix!r}, which holds none of the written "
            f"objects {part_keys!r}"
        )
        assert part["StorageDescriptor"]["SerdeInfo"]["SerializationLibrary"], (
            f"partition {dt!r} carries no SerDe: {part['StorageDescriptor']!r}"
        )

    # The job may only ADD partitions: the definition this check registered must survive.
    table = glue.get_table(DatabaseName=database, Name=tgt_table)["Table"]
    assert [k["Name"] for k in table["PartitionKeys"]] == ["dt"], (
        f"the run rewrote the partition keys to {table['PartitionKeys']!r}"
    )
    assert {c["Name"] for c in table["StorageDescriptor"]["Columns"]} == {"order_id",
                                                                         "amount"}, (
        f"the run rewrote the declared columns to "
        f"{table['StorageDescriptor']['Columns']!r}"
    )
    assert table["StorageDescriptor"]["Location"].rstrip("/") == \
        target_location.rstrip("/"), (
        f"the run relocated the table to {table['StorageDescriptor']['Location']!r}, "
        f"expected {target_location!r}"
    )

    # 300 (not 301) source rows proves skip.header.line.count governed the catalog read; the
    # doubled total is re-read from the written Parquet, so a pass-through job cannot match it.
    marker = _get_object(s3, bucket, marker_key)
    assert marker is not None, (
        f"the job wrote no marker at {marker_key!r}, so it never re-read its own output"
    )
    expected_marker = ("%d|amount,dt,order_id|%d|%.1f|amount,dt,order_id"
                       % (_ROWS, _ROWS, _DOUBLED_TOTAL)).encode()
    assert marker.strip() == expected_marker, (
        f"the catalog-driven read and the re-read of the written Parquet reported "
        f"{marker!r}, expected {expected_marker!r} "
        f"(src_rows|src_cols|out_rows|sum(amount)|out_cols)"
    )

    glue.delete_job(JobName=job)
    code, status, message = _error(lambda: glue.get_job(JobName=job))
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException for the deleted job, got {code}"
    assert status == 400, f"expected HTTP 400 for GetJob of the deleted job, got {status}"
    expected_message = "Job not found."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"
    listed_jobs = [
        name
        for page in glue.get_paginator("list_jobs").paginate(Tags={"sim2real": CHECK})
        for name in page["JobNames"]
    ]
    assert job not in listed_jobs, "the deleted job is still listed by ListJobs filtered to this check's tag"
    code, status, message = _error(lambda: glue.start_job_run(JobName=job))
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException starting the deleted job, got {code}"
    assert status == 400, f"expected HTTP 400 for StartJobRun of the deleted job, got {status}"
    expected_message = "Failed to start job run due to missing metadata."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    glue.delete_table(DatabaseName=database, Name=tgt_table)
    code, status, message = _error(lambda: glue.get_table(DatabaseName=database, Name=tgt_table))
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException for the deleted table, got {code}"
    assert status == 400, f"expected HTTP 400 for GetTable of the deleted table, got {status}"
    expected_message = "Entity Not Found"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"
    listed_tables = [
        t["Name"]
        for page in glue.get_paginator("get_tables").paginate(DatabaseName=database)
        for t in page["TableList"]
    ]
    assert tgt_table not in listed_tables, f"GetTables still lists the deleted table: {listed_tables!r}"
    assert src_table in listed_tables, f"GetTables lost the untouched source table: {listed_tables!r}"
    code, status, message = _error(lambda: glue.get_partitions(DatabaseName=database, TableName=tgt_table))
    assert code == "EntityNotFoundException", (
        f"expected EntityNotFoundException for GetPartitions on the deleted table, got {code}"
    )
    expected_message = f"Table {tgt_table} not found."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its ClientError (code, HTTP status, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return (
            exc.response.get("Error", {}).get("Code"),
            exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            exc.response.get("Error", {}).get("Message") or "",
        )
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_bucket(ctx, s3, bucket: str) -> None:
    # us-east-1 is S3's one region that refuses an explicit LocationConstraint.
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
    # bounded retry in _run_job_to_terminal absorbs the propagation window.
    return arn


def _run_job_to_terminal(glue, job: str, arguments: dict, *, deadline: float) -> dict:
    """Start the job and poll to a terminal state, retrying the IAM-propagation failure: Glue
    reports an unassumable role as a FAILED run, not as a StartJobRun error."""
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
    raise AssertionError(
        f"job {job} reached no terminal run state within the suite budget; last state "
        f"{record.get('JobRunState')!r}"
    )


def _list_partitions(glue, database: str, table: str) -> list:
    parts = []
    for page in glue.get_paginator("get_partitions").paginate(DatabaseName=database,
                                                              TableName=table):
        parts.extend(page.get("Partitions", []))
    return parts


def _list_partition_values(glue, database: str, table: str) -> list:
    return sorted(p["Values"] for p in _list_partitions(glue, database, table))


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
    """Delete with a bounded retry on throttling and dependency conflicts; a resource already
    gone counts as deleted."""
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
