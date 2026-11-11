"""stop-query-execution-terminal-is-noop."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "stop-query-execution-terminal-is-noop"
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
    # us-east-1 is the only region CreateBucket rejects a LocationConstraint for.
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "stop-query-execution-terminal-is-noop"}]},
    )
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

@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StopQueryExecution on an already-terminal query succeeds and leaves its SUCCEEDED or FAILED
    state unchanged; it neither flips it to CANCELLED nor rejects the call."""
    athena = ctx.client("athena")
    out = _output_location(ctx)
    qid = _start_query(athena, out, "SELECT 1")

    final_state = _wait_terminal(athena, qid, timeout_s=120)
    assert final_state in ("SUCCEEDED", "FAILED", "CANCELLED"), (
        f"_wait_terminal contract violated: returned non-terminal state {final_state}"
    )

    try:
        athena.stop_query_execution(QueryExecutionId=qid)
        code = None
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code") or type(exc).__name__
    assert code is None, f"StopQueryExecution on a terminal query must be an accepted no-op, got {code}"

    after = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
    assert after == final_state, (
        f"terminal state must be immutable: was {final_state}, became {after} after StopQueryExecution"
    )

    # A second stop is likewise a no-op, and results stay readable for a SUCCEEDED run.
    try:
        athena.stop_query_execution(QueryExecutionId=qid)
        code = None
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code") or type(exc).__name__
    assert code is None, f"repeated StopQueryExecution must stay a no-op, got {code}"

    if final_state == "SUCCEEDED":
        results = athena.get_query_results(QueryExecutionId=qid)
        assert "ResultSet" in results, "results of a SUCCEEDED query must remain readable after a no-op stop"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
