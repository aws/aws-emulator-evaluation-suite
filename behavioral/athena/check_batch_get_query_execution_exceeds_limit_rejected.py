"""batch-get-query-execution-exceeds-limit-rejected."""
from __future__ import annotations

import uuid
from typing import Any

from behavioral_harness import tags

CHECK = "batch-get-query-execution-exceeds-limit-rejected"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchGetQueryExecution with 51 ids fails InvalidRequestException as a whole, while 50 ids
    including the same real execution id are accepted, so only the count differs between calls."""
    athena = ctx.client("athena")
    bucket = _create_results_bucket(ctx)
    real_id = _start_and_wait(ctx, athena, bucket)

    bogus_ids = [str(uuid.uuid4()) for _ in range(50)]

    too_many = [real_id] + bogus_ids
    code, message = _error(lambda: athena.batch_get_query_execution(QueryExecutionIds=too_many))
    assert code == "InvalidRequestException", (
        f"expected InvalidRequestException for 51 ids (1 real + 50 bogus), got {code!r}"
    )
    assert message == (
        "1 validation error detected: Value at 'queryExecutionIds' failed to satisfy constraint: "
        "Member must have length less than or equal to 50"
    ), repr(message)

    exactly_fifty = [real_id] + bogus_ids[:49]
    resp = athena.batch_get_query_execution(QueryExecutionIds=exactly_fifty)
    resolved_ids = [qe["QueryExecutionId"] for qe in resp["QueryExecutions"]]
    assert resolved_ids == [real_id], f"expected only {real_id} resolved, got {resolved_ids}"
    unprocessed_ids = {u["QueryExecutionId"] for u in resp["UnprocessedQueryExecutionIds"]}
    assert unprocessed_ids == set(bogus_ids[:49]), (
        f"expected 49 unprocessed bogus ids, got {resp['UnprocessedQueryExecutionIds']}"
    )


def _create_results_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-bgqel-")
    kwargs: dict[str, Any] = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return bucket


def _empty_and_delete_bucket(ctx: Any, bucket: str) -> None:
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=bucket)
    keys = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
    if keys:
        s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})
    s3.delete_bucket(Bucket=bucket)


def _start_and_wait(ctx: Any, athena, bucket: str, timeout_s: float = 90.0) -> str:
    import time

    qid = athena.start_query_execution(
        QueryString="SELECT 1 AS n",
        ResultConfiguration={"OutputLocation": f"s3://{bucket}/results/"},
    )["QueryExecutionId"]
    deadline = time.monotonic() + timeout_s
    state = "QUEUED"
    while time.monotonic() < deadline:
        state = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            break
        time.sleep(2)
    assert state == "SUCCEEDED", f"query {qid} ended in {state!r}, not SUCCEEDED"
    return qid


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
