"""query-execution-failed-query-then-results-unavailable."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "query-execution-failed-query-then-results-unavailable"
GROUP = 'query-execution'
SERVICES = ['athena']

def _empty_and_delete_bucket(s3, bucket):
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


def _output_location(ctx):
    """Create an Athena query-results bucket (region-correct) and return its s3:// prefix."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-athena-results-")
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    return f"s3://{bucket}/results/"

def _start_query(athena, out, query_string, workgroup=None, client_request_token=None, database=None):
    kwargs = {"QueryString": query_string, "ResultConfiguration": {"OutputLocation": out}}
    if workgroup:
        kwargs["WorkGroup"] = workgroup
    if client_request_token:
        kwargs["ClientRequestToken"] = client_request_token
    if database:
        kwargs["QueryExecutionContext"] = {"Database": database}
    return athena.start_query_execution(**kwargs)["QueryExecutionId"]

def _wait_terminal(athena, qid, timeout_s=30, interval_s=1):
    terminal = ("SUCCEEDED", "FAILED", "CANCELLED")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
        if state in terminal:
            return state
        time.sleep(interval_s)
    raise AssertionError(f"query {qid} did not reach a terminal state within {timeout_s}s (last={state})")

@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A query on an unresolvable table ends FAILED with a USER-category AthenaError and GetQueryResults
    then errors, while a valid query succeeds and its results read back."""
    athena = ctx.client("athena")
    out = _output_location(ctx)

    good_qid = _start_query(athena, out, "SELECT 1 AS n")
    good_state = _wait_terminal(athena, good_qid, timeout_s=90)
    assert good_state == "SUCCEEDED", f"control query expected SUCCEEDED, got {good_state}"
    good_rows = athena.get_query_results(QueryExecutionId=good_qid)["ResultSet"]["Rows"]
    assert [d.get("VarCharValue") for d in good_rows[-1]["Data"]] == ["1"], (
        f"control query result mismatch: {good_rows}"
    )

    missing_schema = "sim2real_behav_no_such_db_xyz"
    qid = _start_query(athena, out, f"SELECT * FROM {missing_schema}.no_such_table_xyz")

    state = _wait_terminal(athena, qid, timeout_s=90)
    assert state == "FAILED", f"expected FAILED, got {state}"

    exec_info = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
    assert exec_info["Status"]["State"] == "FAILED"
    expected_reason = f"SCHEMA_NOT_FOUND: line 1:15: Schema '{missing_schema}' does not exist"
    reason = exec_info["Status"].get("StateChangeReason")
    assert reason == expected_reason, f"unexpected StateChangeReason: {reason!r}"

    athena_error = exec_info["Status"].get("AthenaError")
    assert athena_error, f"FAILED query should carry an AthenaError envelope, got {exec_info['Status']}"
    assert athena_error["ErrorCategory"] == 2, (
        f"an unresolvable schema/table is a customer (USER) error, category 2, "
        f"got {athena_error['ErrorCategory']}"
    )
    assert athena_error.get("ErrorMessage") == expected_reason, (
        f"unexpected AthenaError.ErrorMessage: {athena_error.get('ErrorMessage')!r}"
    )

    try:
        athena.get_query_results(QueryExecutionId=qid)
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code") or type(exc).__name__
        message = getattr(exc, "response", {}).get("Error", {}).get("Message")
    else:
        raise AssertionError("real AWS rejects GetQueryResults on a FAILED query, but it SUCCEEDED")
    assert code == "InvalidRequestException", (
        f"expected results-unavailable error for FAILED query, got {code}"
    )
    assert message == "Query did not finish successfully. Final query state: FAILED", (
        f"unexpected GetQueryResults refusal message: {message!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
