"""query-execution-syntax-error-rejected-synchronously."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "query-execution-syntax-error-rejected-synchronously"
GROUP = "overly-permissive"
SERVICES = ["athena"]


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


# A failure marker used narrowly: only when the target ACCEPTED unparseable SQL, which means it
# has no parser and therefore no engine. A wrong-but-present error code gets no marker.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: The statement keywords the engine's parser lists after a mismatched first token, verbatim.
_EXPECTING = (
    "'ALTER', 'ANALYZE', 'CALL', 'COMMENT', 'COMMIT', 'CREATE', 'DEALLOCATE', 'DELETE', 'DENY', "
    "'DESC', 'DESCRIBE', 'DROP', 'EXECUTE', 'EXPLAIN', 'GRANT', 'INSERT', 'MERGE', 'PREPARE', "
    "'REFRESH', 'RESET', 'REVOKE', 'ROLLBACK', 'SET', 'SHOW', 'START', 'TRUNCATE', 'UNLOAD', "
    "'UPDATE', 'USE', <query>"
)


def _start_query(
    athena, out, query_string, workgroup=None, client_request_token=None, database=None
):
    kwargs = {
        "QueryString": query_string,
        "ResultConfiguration": {"OutputLocation": out},
    }
    if workgroup:
        kwargs["WorkGroup"] = workgroup
    if client_request_token:
        kwargs["ClientRequestToken"] = client_request_token
    if database:
        kwargs["QueryExecutionContext"] = {"Database": database}
    return athena.start_query_execution(**kwargs)["QueryExecutionId"]


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A parse error must be rejected by StartQueryExecution, not accepted then FAILED."""
    athena = ctx.client("athena")
    out = _output_location(ctx)

    # Positive control: the same call, on the same output location, with valid SQL succeeds.
    # Without this, a target that rejects every StartQueryExecution call (e.g. a misconfigured
    # output location) would score InvalidRequestException here without ever exercising a parser.
    control_qid = _start_query(athena, out, "SELECT 1")
    assert control_qid, "expected a syntactically valid query to be accepted"

    message = None
    try:
        _start_query(athena, out, "SELEC 1 THIS IS NOT VALID SQL")
        code = None
    except Exception as exc:
        code = (
            getattr(exc, "response", {}).get("Error", {}).get("Code")
            or type(exc).__name__
        )
        message = getattr(exc, "response", {}).get("Error", {}).get("Message")
    prefix = f"{DATAPLANE_MARKER}: " if code is None else ""
    assert code == "InvalidRequestException", (
        f"{prefix}expected unparseable SQL to be rejected at submit time, got {code}"
    )
    assert message == f"line 1:1: mismatched input 'SELEC'. Expecting: {_EXPECTING}", (
        f"unexpected parser error message: {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
