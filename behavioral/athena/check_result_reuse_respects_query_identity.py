"""result-reuse-respects-query-identity."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "result-reuse-respects-query-identity"
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
    # us-east-1 is S3's implicit default region: CreateBucket there REJECTS an explicit
    # LocationConstraint, so the literal below is S3's own region quirk, not a pinned target.
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    # registered BEFORE the name is used anywhere else
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
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


def _data_rows(results):
    """GetQueryResults rows for a SELECT: row 0 repeats the column names, so the data
    rows are rows[1:]. Returned as a LIST (a sequence), never a set — ORDER BY makes
    the order a server-side guarantee and an emulator that shuffles must fail."""
    rows = results["ResultSet"]["Rows"]
    return [[d.get("VarCharValue") for d in r["Data"]] for r in rows[1:]]



@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ResultReuseByAgeConfiguration must reuse a previous result for the SAME query and must
    NOT reuse it for a DIFFERENT one, and a reused execution must report
    DataScannedInBytes == 0."""
    athena = ctx.client("athena")
    out = _output_location(ctx)
    database, table, _ = _external_table(ctx, athena, out)

    reuse = {"ResultReuseByAgeConfiguration": {"Enabled": True, "MaxAgeInMinutes": 60}}
    sql_a = f"SELECT id, name FROM {_dml_name(database, table)} ORDER BY id"
    sql_b = f"SELECT id, name FROM {_dml_name(database, table)} WHERE id = 1"

    def _reuse_info(qid):
        stats = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Statistics"]
        return stats, stats.get("ResultReuseInformation")

    # --- leg 1: first run of A has nothing to reuse ---
    qid1 = _start_query(athena, out, sql_a, database=database, ResultReuseConfiguration=reuse)
    state1 = _wait_terminal(athena, qid1)
    assert state1 == "SUCCEEDED", (
        f"leg 1 (first run of query A) must reach SUCCEEDED, got {state1}: "
        f"{athena.get_query_execution(QueryExecutionId=qid1)['QueryExecution']['Status'].get('StateChangeReason')}"
    )
    stats1, info1 = _reuse_info(qid1)
    assert info1 is not None, (
        "a query that requested result reuse must report ResultReuseInformation in Statistics"
    )
    assert info1["ReusedPreviousResult"] is False, (
        "the first run of a query has no previous result to reuse, got "
        f"ReusedPreviousResult={info1['ReusedPreviousResult']!r}"
    )
    assert stats1["DataScannedInBytes"] > 0, (
        f"the first run really scanned S3, got DataScannedInBytes={stats1['DataScannedInBytes']}"
    )
    rows1 = _data_rows(athena.get_query_results(QueryExecutionId=qid1))
    assert rows1 == [["1", "alpha"], ["2", "bravo"], ["3", "charlie"]], rows1

    # --- leg 2: identical query inside the window reuses, and scans nothing ---
    qid2 = _start_query(athena, out, sql_a, database=database, ResultReuseConfiguration=reuse)
    state2 = _wait_terminal(athena, qid2)
    assert state2 == "SUCCEEDED", (
        f"leg 2 (rerun of query A) must reach SUCCEEDED, got {state2}: "
        f"{athena.get_query_execution(QueryExecutionId=qid2)['QueryExecution']['Status'].get('StateChangeReason')}"
    )
    assert qid2 != qid1, "a reused result is still a distinct QueryExecution, not the same id"
    stats2, info2 = _reuse_info(qid2)
    assert info2 is not None and info2["ReusedPreviousResult"] is True, (
        f"an identical query inside MaxAgeInMinutes=60 must reuse the previous result, got "
        f"{info2!r}"
    )
    assert stats2["DataScannedInBytes"] == 0, (
        f"a reused result scans nothing, so DataScannedInBytes must be exactly 0, got "
        f"{stats2['DataScannedInBytes']}"
    )
    assert _data_rows(athena.get_query_results(QueryExecutionId=qid2)) == rows1, (
        "a reused result must be byte-identical to the result it reused"
    )

    # --- leg 3: a DIFFERENT query must NOT be served A's rows ---
    qid3 = _start_query(athena, out, sql_b, database=database, ResultReuseConfiguration=reuse)
    state3 = _wait_terminal(athena, qid3)
    assert state3 == "SUCCEEDED", (
        f"leg 3 (query B) must reach SUCCEEDED, got {state3}: "
        f"{athena.get_query_execution(QueryExecutionId=qid3)['QueryExecution']['Status'].get('StateChangeReason')}"
    )
    _, info3 = _reuse_info(qid3)
    assert info3 is not None and info3["ReusedPreviousResult"] is False, (
        f"a different query string has no cached result of its own to reuse, got {info3!r}"
    )
    rows3 = _data_rows(athena.get_query_results(QueryExecutionId=qid3))
    assert rows3 == [["1", "alpha"]], (
        f"query B must return B's single row, not A's cached three rows; got {rows3}"
    )

    # --- leg 4: reuse NOT requested -> the query must be run afresh ---
    qid4 = _start_query(athena, out, sql_a, database=database)
    state4 = _wait_terminal(athena, qid4)
    assert state4 == "SUCCEEDED", (
        f"leg 4 (query A without ResultReuseConfiguration) must reach SUCCEEDED, got {state4}: "
        f"{athena.get_query_execution(QueryExecutionId=qid4)['QueryExecution']['Status'].get('StateChangeReason')}"
    )
    stats4, info4 = _reuse_info(qid4)
    assert info4 is None or info4["ReusedPreviousResult"] is False, (
        f"reuse was not requested, so no result may be reused; got {info4!r}"
    )
    assert stats4["DataScannedInBytes"] > 0, (
        f"a query that did not request reuse must really scan, got "
        f"DataScannedInBytes={stats4['DataScannedInBytes']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
