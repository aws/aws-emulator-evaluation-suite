"""query-execution-stop-then-get-shows-cancelled."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-execution-stop-then-get-shows-cancelled"
GROUP = 'query-execution'
SERVICES = ['athena']

def _empty_and_delete_bucket(s3, bucket, timeout_s=30):
    # Athena can still land an async manifest/metadata object into the output
    # prefix a moment after StopQueryExecution reports CANCELLED, which races this
    # teardown's list-then-delete and turns DeleteBucket into BucketNotEmpty.
    deadline = time.monotonic() + timeout_s
    while True:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                s3.delete_objects(
                    Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
                )
        try:
            s3.delete_bucket(Bucket=bucket)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "BucketNotEmpty" or time.monotonic() >= deadline:
                raise
            time.sleep(1)


def _output_location(ctx):
    """Create an Athena query-results bucket (region-correct) and return its s3:// prefix."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-athena-results-")
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]})
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
    """StopQueryExecution drives an in-flight query to CANCELLED, and a repeated stop on the terminal
    execution is accepted as a no-op that leaves it CANCELLED."""
    athena = ctx.client("athena")
    out = _output_location(ctx)
    qid = _start_query(athena, out, "SELECT 1 AS col1")
    athena.stop_query_execution(QueryExecutionId=qid)

    state = _wait_terminal(athena, qid, timeout_s=90)
    assert state == "CANCELLED", f"expected CANCELLED after StopQueryExecution, got {state}"

    # idempotent re-stop on a terminal execution: accepted, state unchanged
    athena.stop_query_execution(QueryExecutionId=qid)
    current = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
    assert current == "CANCELLED", "re-stop must not change a terminal state"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
