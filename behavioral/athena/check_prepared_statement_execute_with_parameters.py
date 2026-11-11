"""prepared-statement-execute-with-parameters."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "prepared-statement-execute-with-parameters"
GROUP = 'prepared-statement'
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




def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")

def run(ctx) -> None:
    """EXECUTE with ExecutionParameters binds the parameter as a VALUE: the bound row and nothing
    else comes back, and a parameter the placeholder's type cannot accept (`2 OR 1=1`) fails the
    execution with TYPE_MISMATCH rather than widening the result set."""
    athena = ctx.client("athena")
    out = _output_location(ctx)
    database, table, _ = _external_table(ctx, athena, out)

    wg = ctx.unique_name("sim2real-behav-wg-exec-")
    athena.create_work_group(
        Name=wg,
        Configuration={"ResultConfiguration": {"OutputLocation": out}},
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))

    stmt = ctx.unique_name("sim2real-behav-stmt_").replace("-", "_")
    ctx.on_cleanup(lambda: athena.delete_prepared_statement(StatementName=stmt, WorkGroup=wg))
    athena.create_prepared_statement(
        StatementName=stmt,
        WorkGroup=wg,
        QueryStatement=f"SELECT id, name FROM {_dml_name(database, table)} WHERE id = ?",
    )

    # --- positive: the parameter is bound and selects exactly its row ---
    qid = _start_query(
        athena,
        out,
        f"EXECUTE {stmt}",
        workgroup=wg,
        database=database,
        ExecutionParameters=["2"],
    )
    state = _wait_terminal(athena, qid)
    assert state == "SUCCEEDED", f"EXECUTE with a valid parameter must succeed, got {state}"

    exec_info = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
    # Real AWS records the submitted statement VERBATIM -- it does not substitute the
    # prepared statement's text and it does not echo ExecutionParameters (absent both here and
    # for a direct `WHERE id = ?` QueryString).
    # So the three observable facts about the execution are asserted instead of the echo: the
    # verbatim query text, the EXECUTE substatement classification, and the ABSENCE of the
    # parameter echo -- an emulator that helpfully echoes ExecutionParameters is wrong.
    assert exec_info["Query"] == f"EXECUTE {stmt}", (
        f"GetQueryExecution must record the submitted statement verbatim, got "
        f"{exec_info.get('Query')!r}"
    )
    assert exec_info["SubstatementType"] == "EXECUTE", (
        f"an EXECUTE of a prepared statement is SubstatementType EXECUTE (StatementType DML), "
        f"got {exec_info.get('SubstatementType')!r}"
    )
    assert "ExecutionParameters" not in exec_info, (
        f"real Athena does not echo ExecutionParameters on QueryExecution, got "
        f"{exec_info.get('ExecutionParameters')!r}"
    )
    rows = _data_rows(athena.get_query_results(QueryExecutionId=qid))
    assert rows == [["2", "bravo"]], (
        f"the bound parameter must select exactly the id=2 row, got {rows}"
    )

    # --- negative: break exactly one thing, the parameter's value ---
    injection = "2 OR 1=1"
    # Real AWS accepts the submission and fails the execution during analysis, so the
    # parameter is bound as a VALUE; a synchronous refusal raises out of _start_query.
    bad_qid = _start_query(
        athena,
        out,
        f"EXECUTE {stmt}",
        workgroup=wg,
        database=database,
        ExecutionParameters=[injection],
    )
    bad_state = _wait_terminal(athena, bad_qid)
    assert bad_state == "FAILED", (
        f"a parameter of {injection!r} cannot bind to an integer placeholder, so the "
        f"execution must reach FAILED, got {bad_state}"
    )
    bad_reason = athena.get_query_execution(QueryExecutionId=bad_qid)["QueryExecution"]["Status"].get(
        "StateChangeReason"
    )
    expected_reason = (
        "TYPE_MISMATCH: line 1:48: Logical expression term must evaluate to a boolean (actual: integer)"
    )
    assert bad_reason == expected_reason, (
        f"the injected execution must fail analysis with {expected_reason!r}, got {bad_reason!r}"
    )
    # effect absent: no rows were produced for the injected parameter
    results = _error(lambda: athena.get_query_results(QueryExecutionId=bad_qid))
    expected = ("InvalidRequestException", "Query did not finish successfully. Final query state: FAILED")
    assert results == expected, (
        f"GetQueryResults on the FAILED injected execution must be refused with {expected!r}, "
        f"got {results!r}"
    )

    # --- control: the statement still works, and still binds only its own row ---
    ctrl_qid = _start_query(
        athena,
        out,
        f"EXECUTE {stmt}",
        workgroup=wg,
        database=database,
        ExecutionParameters=["3"],
    )
    ctrl_state = _wait_terminal(athena, ctrl_qid)
    assert ctrl_state == "SUCCEEDED", (
        f"the control EXECUTE with a valid parameter must still succeed, got {ctrl_state}"
    )
    ctrl_rows = _data_rows(athena.get_query_results(QueryExecutionId=ctrl_qid))
    assert ctrl_rows == [["3", "charlie"]], (
        f"the control execution must still bind exactly one row, got {ctrl_rows}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
