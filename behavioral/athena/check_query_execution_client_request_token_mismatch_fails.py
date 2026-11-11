"""query-execution-client-request-token-mismatch-fails."""
from __future__ import annotations

import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "query-execution-client-request-token-mismatch-fails"
GROUP = 'overly-permissive'
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
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "query-execution-client-request-token-mismatch-fails"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})
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

@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Reusing a ClientRequestToken with a DIFFERENT query string must fail, not silently run,
    and the original query execution submitted under that token must be left unaffected."""
    athena = ctx.client("athena")
    out = _output_location(ctx)
    token = f"sim2real-behav-tok-{uuid.uuid4().hex}"
    first_id = _start_query(athena, out, "SELECT 1 AS a", client_request_token=token)

    try:
        _start_query(athena, out, "SELECT 2 AS b", client_request_token=token)
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code") or type(exc).__name__
        message = getattr(exc, "response", {}).get("Error", {}).get("Message")
    else:
        raise AssertionError("real AWS rejects a reused ClientRequestToken with a different "
                             "query string, but StartQueryExecution SUCCEEDED")
    assert code == "InvalidRequestException", (
        f"expected token-reuse conflict to be rejected, got {code}"
    )
    assert message == "Idempotent parameters do not match", (
        f"unexpected token-reuse refusal message: {message!r}"
    )

    unchanged = athena.get_query_execution(QueryExecutionId=first_id)["QueryExecution"]
    assert unchanged["Query"] == "SELECT 1 AS a", (
        f"rejected mismatch must not disturb the original execution, got query={unchanged['Query']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
