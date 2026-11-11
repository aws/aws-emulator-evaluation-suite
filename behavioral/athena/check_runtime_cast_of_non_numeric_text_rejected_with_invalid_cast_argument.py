"""runtime-cast-of-non-numeric-text-rejected-with-invalid-cast-argument."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "runtime-cast-of-non-numeric-text-rejected-with-invalid-cast-argument"
GROUP = "query-execution"
SERVICES = ["athena"]

# One non-numeric token in every row: the engine quotes the offending value in the reason, so a
# single value keeps the exact reason deterministic.
_LABEL = "not_a_number"
_AMOUNTS = (5, 40, -3)


def _dataset():
    """The CSV bytes built from _LABEL and _AMOUNTS."""
    return "".join(f"{i},{_LABEL},{amt}\n" for i, amt in enumerate(_AMOUNTS)).encode()


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


def _wait_terminal(athena, qid, timeout_s=240, interval_s=2):
    """Poll GetQueryExecution to a terminal state within a bound; callers assert which state."""
    terminal = ("SUCCEEDED", "FAILED", "CANCELLED")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_query_execution(
            QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
        if state in terminal:
            return state
        time.sleep(interval_s)
    raise AssertionError(
        f"query {qid} did not reach a terminal state within {timeout_s}s (last={state!r})")


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
    """The AWS error (code, message) raised by `fn`; an unexpected success raises."""
    try:
        fn()
    except Exception as exc:  # botocore ClientError and its service-specific subclasses
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if not code:
            raise AssertionError(
                f"expected a service error carrying an error code, got {exc!r}") from exc
        return code, getattr(exc, "response", {}).get("Error", {}).get("Message")
    raise AssertionError("the call SUCCEEDED where real AWS rejects it")


def _keys_for_query(s3, bucket, prefix, qid):
    """Every object Athena wrote for one query id, paginated."""
    found = []
    for page in s3.get_paginator("list_objects_v2").paginate(
            Bucket=bucket, Prefix=f"{prefix}{qid}"):
        for obj in page.get("Contents", []):
            found.append(obj["Key"])
    return sorted(found)


@tags("axis:rejection", "cap:c2", "cap:c3", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Casting non-numeric text to integer fails at runtime with the exact INVALID_CAST_ARGUMENT
    reason, a non-retryable user AthenaError (type 1100), no result object, and a rejected
    GetQueryResults; a control cast on the same table succeeds with exact rows.

    Reference: https://docs.aws.amazon.com/athena/latest/ug/error-reference.html
    """
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    results_bucket = _make_bucket(ctx, "sim2real-behav-athena-results-")
    prefix = "results/"
    out = f"s3://{results_bucket}/{prefix}"
    data_bucket = _make_bucket(ctx, "sim2real-behav-athena-data-")

    body = _dataset()
    # Fixture guard: the label must really be non-numeric for the cast below to fail.
    assert not _LABEL.lstrip("-").isdigit(), (
        f"_LABEL must be un-castable to an integer for this check to mean anything, got {_LABEL!r}")
    s3.put_object(Bucket=data_bucket, Key="src/rows.csv", Body=body)

    database = ctx.unique_name("sim2real-behav-db-").replace("-", "_")
    table = ctx.unique_name("sim2real-behav-cast-").replace("-", "_")
    # Registered BEFORE the CREATE it undoes: CASCADE drops the table too, and DROP DATABASE is
    # itself an Athena query, so LIFO keeps the results bucket alive until after it runs.
    ctx.on_cleanup(lambda: _run_sql(athena, out, f"DROP DATABASE IF EXISTS `{database}` CASCADE"))
    _run_sql(athena, out, f"CREATE DATABASE `{database}`")
    _run_sql(
        athena, out,
        f"CREATE EXTERNAL TABLE `{database}`.`{table}` "
        "(`id` int, `label` string, `amount` bigint) "
        "ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' STORED AS TEXTFILE "
        f"LOCATION 's3://{data_bucket}/src/'")

    table_name = _dml_name(database, table)

    # The SQL is valid and the table real, so only reading the data can produce this failure.
    bad_qid = _start_query(
        athena, out,
        f"SELECT CAST(label AS integer) FROM {table_name}", database=database)
    bad_state = _wait_terminal(athena, bad_qid)
    bad_status = athena.get_query_execution(
        QueryExecutionId=bad_qid)["QueryExecution"]["Status"]
    assert bad_state == "FAILED", (
        f"casting the non-numeric value {_LABEL!r} to an integer must fail the execution rather "
        f"than yield a null or a zero, got {bad_state!r} (reason "
        f"{bad_status.get('StateChangeReason')!r})")

    reason = bad_status["StateChangeReason"]
    assert reason == f"INVALID_CAST_ARGUMENT: Cannot cast '{_LABEL}' to INT", (
        f"the failure must name the cast error class and quote the offending value so the customer "
        f"can find the bad row, got {reason!r}")

    athena_error = bad_status["AthenaError"]
    assert athena_error["ErrorCategory"] == 2, (
        f"bad data in the customer's own object is a USER-category error (2), got "
        f"ErrorCategory={athena_error['ErrorCategory']!r}")
    assert athena_error["ErrorType"] == 1100, (
        f"real AWS classifies a runtime cast failure as ErrorType 1100, distinct from the 1002 it "
        f"uses for statements rejected while planning, got {athena_error['ErrorType']!r}")
    assert athena_error["Retryable"] is False, (
        f"the same query over the same data cannot succeed on retry, so Retryable must be False, "
        f"got {athena_error['Retryable']!r}")

    leaked = _keys_for_query(s3, results_bucket, prefix, bad_qid)
    assert leaked == [], (
        f"a FAILED execution must leave NO result object under {out} for its id — not even a "
        f"partial one holding the rows it managed to cast — got {leaked!r}")

    code, message = _error(lambda: athena.get_query_results(QueryExecutionId=bad_qid))
    assert code == "InvalidRequestException", (
        f"GetQueryResults on a failed execution must be rejected with InvalidRequestException, got "
        f"{code!r}")
    assert message == "Query did not finish successfully. Final query state: FAILED", (
        f"unexpected GetQueryResults refusal message: {message!r}")

    control_qid = _run_sql(
        athena, out,
        f"SELECT id, CAST(amount AS varchar) FROM {table_name} ORDER BY id", database=database)
    control_rows = _data_rows(athena, control_qid)
    expected = [[str(i), str(amt)] for i, amt in enumerate(_AMOUNTS)]
    assert control_rows == expected, (
        f"the control cast must return the uploaded amounts rendered as text: expected "
        f"{expected!r}, got {control_rows!r}")
    control_keys = _keys_for_query(s3, results_bucket, prefix, control_qid)
    assert control_keys == [f"{prefix}{control_qid}.csv",
                            f"{prefix}{control_qid}.csv.metadata"], (
        f"a SUCCEEDED query must land exactly its result object and metadata sidecar under {out}, "
        f"which is what makes the failed query's empty listing meaningful, got {control_keys!r}")

    # Re-read after the control query finished, so the absence is about a settled location.
    still_absent = _keys_for_query(s3, results_bucket, prefix, bad_qid)
    assert still_absent == [], (
        f"no object for the failed id may appear later either — after a subsequent query completed "
        f"against the same output location, the listing still shows {still_absent!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
