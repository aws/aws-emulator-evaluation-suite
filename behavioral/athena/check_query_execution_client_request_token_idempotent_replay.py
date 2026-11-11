"""query-execution-client-request-token-idempotent-replay."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "query-execution-client-request-token-idempotent-replay"
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
    """Create an Athena query-results bucket (region-correct) and return its s3:// prefix.

    us-east-1 is a region literal, not a hardcoded default: S3's CreateBucket rejects an
    explicit LocationConstraint of us-east-1, so the constraint is omitted only there.
    """
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-athena-results-")
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "behavioral-athena"}]})
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

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Replaying StartQueryExecution with the same token+params returns the same execution id."""
    athena = ctx.client("athena")
    out = _output_location(ctx)
    token = f"sim2real-behav-tok-{uuid.uuid4().hex}"
    query = "SELECT 42 AS answer"

    qid1 = _start_query(athena, out, query, client_request_token=token)
    qid2 = _start_query(athena, out, query, client_request_token=token)

    assert qid1 == qid2, "identical ClientRequestToken+params should replay the same execution"

    # Control: a fresh token on the SAME query must mint a DISTINCT execution. Without this,
    # a target that ignores ClientRequestToken entirely and just returns a fixed/last id for
    # every StartQueryExecution call would pass the assertion above for the wrong reason.
    other_token = f"sim2real-behav-tok-{uuid.uuid4().hex}"
    qid3 = _start_query(athena, out, query, client_request_token=other_token)
    assert qid3 != qid1, "a different ClientRequestToken on the same query must not replay the first execution"

    state = _wait_terminal(athena, qid1, timeout_s=90)
    assert state == "SUCCEEDED", f"replayed execution {qid1} expected to succeed, got {state}"
    _wait_terminal(athena, qid3, timeout_s=90)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
