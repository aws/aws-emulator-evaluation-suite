"""partition-pruning-scans-only-the-selected-partition."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "partition-pruning-scans-only-the-selected-partition"
GROUP = 'query-execution'
SERVICES = ['athena']



def _empty_and_delete_bucket(s3, bucket):
    """Delete EVERY object before DeleteBucket.

    Athena writes its own result artifacts (`<qid>.csv`, `<qid>.csv.metadata`, `<qid>.txt` for
    DDL) into the output location, so a bucket that only ever received our uploads is still
    non-empty at teardown. DeleteBucket on a non-empty bucket fails, and a failed DeleteBucket
    is the single most likely cost leak in this service — hence the paginated delete_objects
    sweep.
    """
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket)


def _make_bucket(ctx, prefix):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(prefix)
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    # registered BEFORE the name is used anywhere else
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    # Tag the bucket so tag-based cleanup can find it.
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "partition-pruning-scans-only-the-selected-partition"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})
    return bucket


def _output_location(ctx):
    return f"s3://{_make_bucket(ctx, 'sim2real-behav-athena-results-')}/results/"


def _start_query(athena, out, query_string, workgroup=None, database=None, **extra):
    kwargs = {"QueryString": query_string, "ResultConfiguration": {"OutputLocation": out}}
    if workgroup:
        kwargs["WorkGroup"] = workgroup
    if database:
        kwargs["QueryExecutionContext"] = {"Database": database}
    kwargs.update(extra)
    return athena.start_query_execution(**kwargs)["QueryExecutionId"]


def _wait_terminal(athena, qid, timeout_s=300, interval_s=2):
    """Poll GetQueryExecution to a REQUIRED terminal state with a bounded deadline.

    A bare time.sleep would not be an assertion; timing out here is a hard failure, not a pass.
    """
    terminal = ("SUCCEEDED", "FAILED", "CANCELLED")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
        if state in terminal:
            return state
        time.sleep(interval_s)
    raise AssertionError(
        f"query {qid} did not reach a terminal state within {timeout_s}s (last={state})")


def _run_sql(athena, out, sql, database=None, workgroup=None, **extra):
    qid = _start_query(athena, out, sql, database=database, workgroup=workgroup, **extra)
    state = _wait_terminal(athena, qid)
    if state != "SUCCEEDED":
        status = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
        raise AssertionError(
            f"statement reached {state}, expected SUCCEEDED: {sql!r} -- "
            f"{status.get('StateChangeReason')}"
        )
    return qid


def _stats(athena, qid):
    return athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Statistics"]


def _data_rows(results):
    """GetQueryResults rows for a SELECT: row 0 repeats the column names, so the data rows are
    rows[1:]. Returned as a LIST (a sequence), never a set — ORDER BY makes the order a
    server-side guarantee and an emulator that shuffles must fail."""
    rows = results["ResultSet"]["Rows"]
    return [[d.get("VarCharValue") for d in r["Data"]] for r in rows[1:]]


def _all_rows(results):
    """Every row, header included. SHOW PARTITIONS emits no header row."""
    rows = results["ResultSet"]["Rows"]
    return [[d.get("VarCharValue") for d in r["Data"]] for r in rows]


def _dml_name(database, table):
    """Fully-qualified table name for a DML (SELECT/INSERT/CTAS) statement.

    Athena parses DDL with the Hive parser, which quotes identifiers with BACKTICKS, but parses
    DML with the Trino parser, which quotes them with DOUBLE QUOTES. A backtick inside a SELECT
    makes the statement unclassifiable and StartQueryExecution refuses it SYNCHRONOUSLY with
    `InvalidRequestException: Queries of this type are not supported`. So the DDL below keeps
    its backticks and every DML statement goes through here.
    """
    return f'"{database}"."{table}"'


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c2", "cap:c3")
def run(ctx) -> None:
    """A WHERE clause on the partition key returns only that partition's rows and reads only its
    bytes: the pruned scan's DataScannedInBytes equals the selected partition object's size
    exactly, and the unpruned scan's equals the sum of both."""
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    out = _output_location(ctx)
    data_bucket = _make_bucket(ctx, "sim2real-behav-athena-data-")

    # Two partitions of deliberately very different size, so the byte counts cannot coincide.
    small_body = b"1\n2\n"                                              # 4 bytes, 2 rows
    big_body = "".join(f"{i}\n" for i in range(1000, 30000)).encode()    # 165000 bytes, 29000 rows
    assert len(small_body) == 4 and len(big_body) == 165000, (
        f"test data changed shape: {len(small_body)!r} / {len(big_body)!r}")
    s3.put_object(Bucket=data_bucket, Key="part/dt=2024-01-01/data.csv", Body=small_body)
    s3.put_object(Bucket=data_bucket, Key="part/dt=2024-01-02/data.csv", Body=big_body)

    database = ctx.unique_name("sim2real-behav-db-").replace("-", "_")
    table = ctx.unique_name("sim2real-behav-tbl-").replace("-", "_")
    # Registered BEFORE the CREATE it undoes: CASCADE also drops the table, and DROP DATABASE is
    # itself an Athena query, so LIFO keeps the results bucket alive until after it runs.
    ctx.on_cleanup(lambda: _run_sql(athena, out, f"DROP DATABASE IF EXISTS `{database}` CASCADE"))
    _run_sql(athena, out, f"CREATE DATABASE `{database}`")
    _run_sql(
        athena, out,
        f"CREATE EXTERNAL TABLE `{database}`.`{table}` (`id` int) "
        "PARTITIONED BY (`dt` string) "
        "ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' STORED AS TEXTFILE "
        f"LOCATION 's3://{data_bucket}/part/'",
    )

    # --- the metastore really discovered both S3 prefixes as partitions ---
    _run_sql(athena, out, f"MSCK REPAIR TABLE `{database}`.`{table}`")
    qp = _run_sql(athena, out, f"SHOW PARTITIONS `{database}`.`{table}`")
    partitions = sorted(r[0] for r in _all_rows(athena.get_query_results(QueryExecutionId=qp)))
    assert partitions == ["dt=2024-01-01", "dt=2024-01-02"], (
        f"MSCK REPAIR TABLE must register both Hive prefixes as partitions, got {partitions!r}")

    tname = _dml_name(database, table)

    # --- leg 1: the partition predicate returns ONLY that partition, and reads only its bytes ---
    q1 = _run_sql(athena, out,
                  f"SELECT id FROM {tname} WHERE dt = '2024-01-01' ORDER BY id", database=database)
    pruned_rows = _data_rows(athena.get_query_results(QueryExecutionId=q1))
    pruned_bytes = _stats(athena, q1)["DataScannedInBytes"]
    assert pruned_rows == [["1"], ["2"]], (
        f"WHERE dt='2024-01-01' must return exactly that partition's two rows, got {pruned_rows!r}")
    assert pruned_bytes == len(small_body), (
        f"the pruned scan must read exactly the {len(small_body)} bytes of "
        f"dt=2024-01-01/data.csv and nothing else, got DataScannedInBytes={pruned_bytes!r}")

    # --- leg 2: no predicate -> the engine reads BOTH partitions, i.e. every byte ---
    q2 = _run_sql(athena, out, f"SELECT count(*) FROM {tname}", database=database)
    full_rows = _data_rows(athena.get_query_results(QueryExecutionId=q2))
    full_bytes = _stats(athena, q2)["DataScannedInBytes"]
    assert full_rows == [["29002"]], (
        f"an unpruned count must see all 2 + 29000 rows, got {full_rows!r}")
    assert full_bytes == len(small_body) + len(big_body), (
        f"the unpruned scan must read both partitions' "
        f"{len(small_body) + len(big_body)} bytes, got DataScannedInBytes={full_bytes!r}")

    # --- leg 3: the OTHER partition alone, so the accounting is per-partition and not a total ---
    q3 = _run_sql(athena, out,
                  f"SELECT count(*) FROM {tname} WHERE dt = '2024-01-02'", database=database)
    other_rows = _data_rows(athena.get_query_results(QueryExecutionId=q3))
    other_bytes = _stats(athena, q3)["DataScannedInBytes"]
    assert other_rows == [["29000"]], (
        f"WHERE dt='2024-01-02' must count exactly that partition's rows, got {other_rows!r}")
    assert other_bytes == len(big_body), (
        f"the second partition's scan must read exactly its {len(big_body)} bytes, got "
        f"DataScannedInBytes={other_bytes!r}")

    # --- the invariant the whole check exists for: pruning is a strict cost reduction ---
    assert pruned_bytes < full_bytes, (
        f"no pruning happened: the predicated query read {pruned_bytes!r} bytes and the "
        f"unpredicated one read {full_bytes!r}")
    assert pruned_bytes + other_bytes == full_bytes, (
        f"the per-partition byte counts must sum to the whole-table count: "
        f"{pruned_bytes!r} + {other_bytes!r} != {full_bytes!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
