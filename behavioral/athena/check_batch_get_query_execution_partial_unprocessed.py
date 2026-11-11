"""batch-get-query-execution-partial-unprocessed."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "batch-get-query-execution-partial-unprocessed"
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
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "batch-get-query-execution-partial-unprocessed"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})
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

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchGetQueryExecution reports unknown ids as unprocessed alongside real results."""
    athena = ctx.client("athena")
    out = _output_location(ctx)
    qid = _start_query(athena, out, "SELECT 1 AS col1")
    _wait_terminal(athena, qid, timeout_s=60)

    bogus_id = "00000000-0000-0000-0000-000000000000"
    resp = athena.batch_get_query_execution(QueryExecutionIds=[qid, bogus_id])

    found_ids = {qe["QueryExecutionId"] for qe in resp["QueryExecutions"]}
    unprocessed_by_id = {u.get("QueryExecutionId"): u for u in resp["UnprocessedQueryExecutionIds"]}
    assert qid in found_ids, f"expected real execution {qid} in QueryExecutions, got {found_ids}"
    assert bogus_id in unprocessed_by_id, (
        f"expected {bogus_id} in UnprocessedQueryExecutionIds, got {list(unprocessed_by_id)}"
    )
    assert bogus_id not in found_ids, f"bogus id {bogus_id} must not appear in QueryExecutions"
    assert unprocessed_by_id[bogus_id].get("ErrorCode"), (
        f"unprocessed entry for {bogus_id} must carry an ErrorCode, got {unprocessed_by_id[bogus_id]}"
    )

    matched = next(qe for qe in resp["QueryExecutions"] if qe["QueryExecutionId"] == qid)
    assert matched["Status"]["State"] == "SUCCEEDED", (
        f"expected {qid} SUCCEEDED, got {matched['Status']['State']}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
