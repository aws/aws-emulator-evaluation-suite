"""query-statistics-reflect-actual-scan."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "query-statistics-reflect-actual-scan"
GROUP = 'query-execution'
SERVICES = ['athena']


_CSV_ROWS = "1,alpha,10.5,true\n2,bravo,20.25,false\n3,charlie,30.75,true\n"


def _empty_and_delete_bucket(s3, bucket):
    """Delete EVERY object before DeleteBucket.

    Athena writes its own result artifacts (`<qid>.csv`, `<qid>.csv.metadata`,
    `<qid>.txt` for DDL) into the output location, so a bucket that only ever
    received our uploads is still non-empty at teardown. DeleteBucket on a
    non-empty bucket fails, and a failed DeleteBucket is the single most likely
    cost leak in this service — hence the paginated delete_objects sweep.
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
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "behavioral"}]})
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

    300s (not the 30-90s the existing athena checks use): a query over a real
    EXTERNAL TABLE additionally pays Glue metadata resolution, split planning and
    S3 listing, and the account's query queue is shared. A bare time.sleep would
    not be an assertion; timing out here is a hard failure, not a pass.
    """
    terminal = ("SUCCEEDED", "FAILED", "CANCELLED")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
        if state in terminal:
            return state
        time.sleep(interval_s)
    raise AssertionError(f"query {qid} did not reach a terminal state within {timeout_s}s (last={state})")


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


def _external_table(ctx, athena, out):
    """Stand up the cheapest real Athena data source: one tiny CSV object in S3 registered
    as a typed EXTERNAL TABLE. Returns (database, table, data_bytes).

    Cleanups are registered at creation time and the runner runs them LIFO, so the
    registration order (results bucket -> data bucket -> DROP DATABASE CASCADE) tears
    down as DROP DATABASE -> data bucket -> results bucket. DROP DATABASE is itself an
    Athena query, so the results bucket must outlive it — which LIFO guarantees.
    """
    s3 = ctx.client("s3")
    data_bucket = _make_bucket(ctx, "sim2real-behav-athena-data-")
    body = _CSV_ROWS.encode()
    s3.put_object(Bucket=data_bucket, Key="data/rows.csv", Body=body)

    database = ctx.unique_name("sim2real-behav-db-").replace("-", "_")
    table = ctx.unique_name("sim2real-behav-tbl-").replace("-", "_")
    ctx.on_cleanup(lambda: _run_sql(athena, out, f"DROP DATABASE IF EXISTS `{database}` CASCADE"))
    _run_sql(athena, out, f"CREATE DATABASE `{database}`")
    _run_sql(
        athena,
        out,
        f"CREATE EXTERNAL TABLE `{database}`.`{table}` "
        "(`id` int, `name` string, `amount` double, `active` boolean) "
        "ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' STORED AS TEXTFILE "
        f"LOCATION 's3://{data_bucket}/data/'",
    )
    return database, table, len(body)


def _dml_name(database, table):
    """Fully-qualified table name for a DML (SELECT/EXECUTE) statement.

    Athena parses DDL with the Hive parser, which quotes identifiers with BACKTICKS, but
    parses DML with the Trino parser, which quotes them with DOUBLE QUOTES. A backtick
    inside a SELECT makes the statement unclassifiable and StartQueryExecution refuses it
    SYNCHRONOUSLY with `InvalidRequestException: Queries of this type are not supported`
    (on real AWS the identical SELECT is
    accepted unquoted or double-quoted, and refused backtick-quoted, while
    a backtick-quoted CREATE EXTERNAL TABLE and SHOW TABLES both succeed).
    So the DDL below keeps its backticks and every DML statement goes through here.
    """
    return f'"{database}"."{table}"'





@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """QueryExecution.Statistics and GetQueryRuntimeStatistics must reflect real work: a
    table scan reports DataScannedInBytes > 0 while a table-free literal reports exactly
    0, and the timings are internally consistent."""
    athena = ctx.client("athena")
    out = _output_location(ctx)
    database, table, data_bytes = _external_table(ctx, athena, out)

    # --- leg 1: a real scan of the S3 objects ---
    qid = _start_query(
        athena, out, f"SELECT id, name, amount FROM {_dml_name(database, table)} ORDER BY id",
        database=database,
    )
    state = _wait_terminal(athena, qid)
    assert state == "SUCCEEDED", f"expected the required terminal SUCCEEDED, got {state}"

    exec_info = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
    stats = exec_info["Statistics"]
    assert stats["DataScannedInBytes"] > 0, (
        f"a scan of {data_bytes} CSV bytes must report DataScannedInBytes > 0, got "
        f"{stats['DataScannedInBytes']}"
    )
    assert stats["EngineExecutionTimeInMillis"] > 0, (
        f"a query that really ran must report EngineExecutionTimeInMillis > 0, got "
        f"{stats['EngineExecutionTimeInMillis']}"
    )
    assert stats["TotalExecutionTimeInMillis"] >= stats["EngineExecutionTimeInMillis"], (
        f"TotalExecutionTimeInMillis ({stats['TotalExecutionTimeInMillis']}) must include "
        f"EngineExecutionTimeInMillis ({stats['EngineExecutionTimeInMillis']})"
    )

    status = exec_info["Status"]
    assert status["CompletionDateTime"] >= status["SubmissionDateTime"], (
        f"CompletionDateTime {status['CompletionDateTime']} precedes SubmissionDateTime "
        f"{status['SubmissionDateTime']}"
    )

    runtime = athena.get_query_runtime_statistics(QueryExecutionId=qid)["QueryRuntimeStatistics"]
    assert runtime["Timeline"]["TotalExecutionTimeInMillis"] > 0, (
        f"GetQueryRuntimeStatistics Timeline must carry a non-zero total, got {runtime['Timeline']}"
    )
    rows = runtime["Rows"]
    assert rows["OutputRows"] == 3, (
        f"the query returned 3 rows, so QueryRuntimeStatistics.Rows.OutputRows must be 3, "
        f"got {rows['OutputRows']}"
    )
    assert rows["InputRows"] >= rows["OutputRows"], (
        f"InputRows ({rows['InputRows']}) cannot be fewer than OutputRows ({rows['OutputRows']})"
    )

    # --- leg 2: a literal that touches no table scans exactly nothing ---
    lit_qid = _start_query(athena, out, "SELECT 1 AS one")
    lit_state = _wait_terminal(athena, lit_qid)
    assert lit_state == "SUCCEEDED", f"expected the required terminal SUCCEEDED, got {lit_state}"
    lit_stats = athena.get_query_execution(QueryExecutionId=lit_qid)["QueryExecution"]["Statistics"]
    assert lit_stats["DataScannedInBytes"] == 0, (
        f"a table-free literal SELECT scans no data, so DataScannedInBytes must be exactly 0, "
        f"got {lit_stats['DataScannedInBytes']} — Statistics is being fabricated"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
