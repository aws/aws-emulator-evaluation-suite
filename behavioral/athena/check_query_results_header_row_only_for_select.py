"""query-results-header-row-only-for-select."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "query-results-header-row-only-for-select"
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
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "query-results-header-row-only-for-select"},
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





@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """The GetQueryResults header-row convention: a SELECT repeats the column names as row
    0, a SHOW statement does not, and a DDL statement returns no rows at all."""
    athena = ctx.client("athena")
    out = _output_location(ctx)
    database, table, _ = _external_table(ctx, athena, out)

    # --- SELECT: row 0 IS the header, then the data rows ---
    qid = _start_query(
        athena, out, f"SELECT id, name FROM {_dml_name(database, table)} ORDER BY id", database=database
    )
    state = _wait_terminal(athena, qid)
    assert state == "SUCCEEDED", f"SELECT expected SUCCEEDED, got {state}"
    sel = athena.get_query_results(QueryExecutionId=qid)
    all_rows = [[d.get("VarCharValue") for d in r["Data"]] for r in sel["ResultSet"]["Rows"]]
    assert all_rows[0] == ["id", "name"], f"SELECT row 0 must repeat the column names: {all_rows[0]}"
    assert len(all_rows) == 4, f"expected 1 header + 3 data rows, got {len(all_rows)}: {all_rows}"

    # --- SHOW: no header. The database holds exactly one table, so SHOW TABLES must
    #     return exactly one row and that row must be the table name itself. ---
    qid = _start_query(athena, out, f"SHOW TABLES IN `{database}`", database=database)
    state = _wait_terminal(athena, qid)
    assert state == "SUCCEEDED", f"SHOW TABLES expected SUCCEEDED, got {state}"
    show_rows = [
        [d.get("VarCharValue") for d in r["Data"]]
        for r in athena.get_query_results(QueryExecutionId=qid)["ResultSet"]["Rows"]
    ]
    assert show_rows == [[table]], (
        f"SHOW TABLES must return exactly the one table with NO header row, got {show_rows}"
    )

    # --- DDL: zero rows, not even a header. DROP TABLE IF EXISTS on a name that does
    #     not exist is a valid DDL statement that succeeds and produces no result set.
    ddl_qid = _run_sql(athena, out, f"DROP TABLE IF EXISTS `{database}`.`no_such_table_ddl`")
    ddl_exec = athena.get_query_execution(QueryExecutionId=ddl_qid)["QueryExecution"]
    assert ddl_exec["StatementType"] == "DDL", (
        f"DROP TABLE must be classified DDL, got {ddl_exec.get('StatementType')}"
    )
    ddl_results = athena.get_query_results(QueryExecutionId=ddl_qid)
    assert ddl_results["ResultSet"]["Rows"] == [], (
        f"a DDL statement returns no rows — not even a header: {ddl_results['ResultSet']['Rows']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
