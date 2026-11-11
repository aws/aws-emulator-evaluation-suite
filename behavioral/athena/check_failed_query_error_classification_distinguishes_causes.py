"""failed-query-error-classification-distinguishes-causes."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "failed-query-error-classification-distinguishes-causes"
GROUP = 'error-semantics'
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


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")

def run(ctx) -> None:
    """Three different SQL defects on the same table fail with distinguishable StateChangeReasons
    and an AthenaError of ErrorCategory 2 (USER) and Retryable False, while a control query on
    the same table succeeds."""
    athena = ctx.client("athena")
    out = _output_location(ctx)
    database, table, _ = _external_table(ctx, athena, out)

    missing_table = "sim2real_behav_no_such_table_zz"
    missing_column = "sim2real_behav_no_such_column_zz"
    cases = {
        "missing-table": f"SELECT id FROM {_dml_name(database, missing_table)}",
        "missing-column": f"SELECT {missing_column} FROM {_dml_name(database, table)}",
        # integer + varchar has no operator in the engine: a type error, not a name error
        "type-error": f"SELECT id + name AS bad FROM {_dml_name(database, table)}",
    }

    observed = {}
    for label, sql in cases.items():
        qid = _start_query(athena, out, sql, database=database)
        state = _wait_terminal(athena, qid)
        assert state == "FAILED", (
            f"{label}: expected the required terminal FAILED for {sql!r}, got {state}"
        )
        status = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
        err = status.get("AthenaError")
        assert err, f"{label}: a FAILED query must carry an AthenaError envelope, got {status}"
        assert err["ErrorCategory"] == 2, (
            f"{label}: a customer SQL defect is ErrorCategory 2 (USER), got {err['ErrorCategory']}"
        )
        assert err["Retryable"] is False, (
            f"{label}: a deterministic SQL defect is not retryable, got Retryable="
            f"{err['Retryable']!r}"
        )
        assert isinstance(err.get("ErrorType"), int), (
            f"{label}: AthenaError.ErrorType must be an integer error code, got "
            f"{err.get('ErrorType')!r}"
        )
        reason = status.get("StateChangeReason") or ""
        assert reason.strip(), f"{label}: StateChangeReason must explain the failure, got {reason!r}"
        observed[label] = (reason, err["ErrorType"])

    # each reason must name the thing that was actually wrong
    assert missing_table in observed["missing-table"][0], (
        f"the missing-table failure must name {missing_table!r}: "
        f"{observed['missing-table'][0]!r}"
    )
    assert missing_column in observed["missing-column"][0], (
        f"the missing-column failure must name {missing_column!r}: "
        f"{observed['missing-column'][0]!r}"
    )

    # and the three must be mutually distinguishable, not one generic message
    reasons = [observed[k][0] for k in cases]
    assert len(set(reasons)) == 3, (
        f"the three defects must produce three distinct StateChangeReasons; a generic "
        f"failure message is a fidelity bug. got {reasons}"
    )

    # control: the same table still answers a valid query
    good_qid = _start_query(
        athena, out, f"SELECT id FROM {_dml_name(database, table)} ORDER BY id", database=database
    )
    assert _wait_terminal(athena, good_qid) == "SUCCEEDED", (
        "the control query over the same table must still succeed after three failures"
    )
    good_rows = _data_rows(athena.get_query_results(QueryExecutionId=good_qid))
    assert good_rows == [["1"], ["2"], ["3"]], (
        f"control query over the same table must return the three seeded rows in order, "
        f"got {good_rows}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
