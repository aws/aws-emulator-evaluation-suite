"""cancelled-scan-writes-no-result-object-and-rejects-results."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "cancelled-scan-writes-no-result-object-and-rejects-results"
GROUP = "query-execution"
SERVICES = ["athena"]

# A four-way self join of 4000 rows is ~2.56e14 tuples over a tiny object: still RUNNING seconds
# later, while scanning very little data.
_N = 4000
_JOIN_WIDTH = 4


def _empty_and_delete_bucket(s3, bucket):
    """Delete every object Athena wrote, then the bucket."""
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
    s3.delete_bucket(Bucket=bucket)


def _make_bucket(ctx, prefix):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(prefix)
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": CHECK},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})
    return bucket


def _start_query(athena, out, query_string, database=None):
    kwargs = {"QueryString": query_string, "ResultConfiguration": {"OutputLocation": out}}
    if database:
        kwargs["QueryExecutionContext"] = {"Database": database}
    return athena.start_query_execution(**kwargs)["QueryExecutionId"]


def _state(athena, qid):
    return athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]


def _wait_terminal(athena, qid, timeout_s=240, interval_s=2):
    """Poll GetQueryExecution to a terminal state within a bound; callers assert which state."""
    terminal = ("SUCCEEDED", "FAILED", "CANCELLED")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = _state(athena, qid)
        if state in terminal:
            return state
        time.sleep(interval_s)
    raise AssertionError(
        f"query {qid} did not reach a terminal state within {timeout_s}s (last={state!r})")


def _wait_running(athena, qid, timeout_s=120, interval_s=1):
    """Poll until the query is RUNNING; reaching a terminal state first fails the check."""
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = _state(athena, qid)
        if state == "RUNNING":
            return
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            raise AssertionError(
                f"the heavy query reached terminal {state!r} before it could be cancelled, so the "
                f"cancellation could not be exercised; make the join wider")
        time.sleep(interval_s)
    raise AssertionError(
        f"query {qid} never reached RUNNING within {timeout_s}s (last={state!r})")


def _run_sql(athena, out, sql, database=None):
    qid = _start_query(athena, out, sql, database=database)
    state = _wait_terminal(athena, qid)
    if state != "SUCCEEDED":
        status = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
        raise AssertionError(
            f"statement reached {state!r}, expected 'SUCCEEDED': {sql!r} -- "
            f"{status.get('StateChangeReason')!r}")
    return qid


def _data_rows(athena, qid):
    """Row 0 of a SELECT ResultSet repeats the column names, so the data rows are rows[1:]."""
    rows = athena.get_query_results(QueryExecutionId=qid)["ResultSet"]["Rows"]
    return [[d.get("VarCharValue") for d in r["Data"]] for r in rows[1:]]


def _dml_name(database, table):
    """DML identifiers are double-quoted (Trino parser); DDL uses backticks (Hive parser)."""
    return f'"{database}"."{table}"'


def _error(fn):
    """The AWS (Error.Code, Error.Message) raised by `fn`; an unexpected success raises."""
    try:
        fn()
    except Exception as exc:  # botocore ClientError and its service-specific subclasses
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if not code:
            raise AssertionError(
                f"expected a service error carrying an error code, got {exc!r}") from exc
        return code, exc.response["Error"].get("Message")
    raise AssertionError("the call SUCCEEDED where real AWS rejects it")


def _keys_for_query(s3, bucket, prefix, qid):
    """Every object Athena wrote for one query id, paginated."""
    found = []
    for page in s3.get_paginator("list_objects_v2").paginate(
            Bucket=bucket, Prefix=f"{prefix}{qid}"):
        for obj in page.get("Contents", []):
            found.append(obj["Key"])
    return sorted(found)


@tags("axis:rejection", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Stopping a RUNNING query yields CANCELLED with reason `Query cancelled by user` and no
    AthenaError, writes no result object for its id, and GetQueryResults is rejected; a control
    query on the same table lands its .csv and .csv.metadata and returns exact rows.

    Reference: https://docs.aws.amazon.com/athena/latest/APIReference/API_StopQueryExecution.html
    """
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    results_bucket = _make_bucket(ctx, "sim2real-behav-athena-results-")
    prefix = "results/"
    out = f"s3://{results_bucket}/{prefix}"
    data_bucket = _make_bucket(ctx, "sim2real-behav-athena-data-")

    body = "".join(f"{i}\n" for i in range(_N)).encode()
    s3.put_object(Bucket=data_bucket, Key="rows/rows.csv", Body=body)

    database = ctx.unique_name("sim2real-behav-db-").replace("-", "_")
    table = ctx.unique_name("sim2real-behav-tbl-").replace("-", "_")
    # Registered BEFORE the CREATE it undoes: CASCADE drops the table too, and DROP DATABASE is
    # itself an Athena query, so LIFO keeps the results bucket alive until after it runs.
    ctx.on_cleanup(lambda: _run_sql(athena, out, f"DROP DATABASE IF EXISTS `{database}` CASCADE"))
    _run_sql(athena, out, f"CREATE DATABASE `{database}`")
    _run_sql(
        athena, out,
        f"CREATE EXTERNAL TABLE `{database}`.`{table}` (`n` bigint) "
        "ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' STORED AS TEXTFILE "
        f"LOCATION 's3://{data_bucket}/rows/'")

    table_name = _dml_name(database, table)

    aliases = [f"t{i}" for i in range(_JOIN_WIDTH)]
    heavy_sql = (
        "SELECT count(*) FROM "
        + ", ".join(f"{table_name} {a}" for a in aliases)
        + " WHERE " + " + ".join(f"{a}.n" for a in aliases) + " > 0")
    heavy_qid = _start_query(athena, out, heavy_sql, database=database)
    # Registered right after the start so a failing assertion cannot leave the query running; a
    # second stop on a terminal execution is a no-op.
    ctx.on_cleanup(lambda: athena.stop_query_execution(QueryExecutionId=heavy_qid))
    _wait_running(athena, heavy_qid)

    athena.stop_query_execution(QueryExecutionId=heavy_qid)
    final_state = _wait_terminal(athena, heavy_qid)
    status = athena.get_query_execution(QueryExecutionId=heavy_qid)["QueryExecution"]["Status"]
    assert final_state == "CANCELLED", (
        f"a RUNNING query that is stopped must reach CANCELLED, not {final_state!r} (reason "
        f"{status.get('StateChangeReason')!r})")
    assert status["StateChangeReason"] == "Query cancelled by user", (
        f"the terminal reason must attribute the stop to the caller, got "
        f"{status['StateChangeReason']!r}")
    assert "AthenaError" not in status, (
        f"a user cancellation is not an engine error, so no AthenaError envelope may be attached, "
        f"got {status.get('AthenaError')!r}")

    cancelled_keys = _keys_for_query(s3, results_bucket, prefix, heavy_qid)
    assert cancelled_keys == [], (
        f"a cancelled execution must leave NO object under {out} for its id, got "
        f"{cancelled_keys!r}")

    code, message = _error(lambda: athena.get_query_results(QueryExecutionId=heavy_qid))
    assert code == "InvalidRequestException", (
        f"GetQueryResults on a cancelled execution must be rejected with InvalidRequestException, "
        f"got {code!r}")
    assert message == "Could not find results", repr(message)

    limit = 3
    control_qid = _run_sql(
        athena, out,
        f"SELECT n FROM {table_name} WHERE n < {limit} ORDER BY n", database=database)
    control_rows = _data_rows(athena, control_qid)
    assert control_rows == [[str(i)] for i in range(limit)], (
        f"the control query must return the {limit} smallest values of the same table, got "
        f"{control_rows!r}")
    control_keys = _keys_for_query(s3, results_bucket, prefix, control_qid)
    assert control_keys == [f"{prefix}{control_qid}.csv",
                            f"{prefix}{control_qid}.csv.metadata"], (
        f"a SUCCEEDED query must land exactly its result object and metadata sidecar under {out}, "
        f"got {control_keys!r}")

    # Re-read after the control query finished, so the absence is about a settled location.
    still_absent = _keys_for_query(s3, results_bucket, prefix, heavy_qid)
    assert still_absent == [], (
        f"no object for the cancelled id may appear later either — after a subsequent query "
        f"completed against the same output location, the listing still shows {still_absent!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
