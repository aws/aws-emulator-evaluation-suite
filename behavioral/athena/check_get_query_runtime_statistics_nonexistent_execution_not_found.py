"""get-query-runtime-statistics-nonexistent-execution-not-found."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "get-query-runtime-statistics-nonexistent-execution-not-found"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetQueryRuntimeStatistics raises InvalidRequestException for a query execution id that was
    never started, while the same call on a real, completed execution returns its statistics."""
    athena = ctx.client("athena")
    bucket = _create_results_bucket(ctx)
    real_id = _start_and_wait(ctx, athena, bucket)

    stats = athena.get_query_runtime_statistics(QueryExecutionId=real_id)["QueryRuntimeStatistics"]
    assert "Timeline" in stats, f"expected Timeline in QueryRuntimeStatistics, got keys={sorted(stats)!r}"
    exec_time = stats["Timeline"]["TotalExecutionTimeInMillis"]
    assert isinstance(exec_time, int) and exec_time >= 0, (
        f"expected a non-negative TotalExecutionTimeInMillis, got {exec_time!r}"
    )

    missing_id = ctx.unique_name("sim2real-athena-qe-missing-")
    code, message = _error(lambda: athena.get_query_runtime_statistics(QueryExecutionId=missing_id))
    assert code == "InvalidRequestException", (
        f"expected InvalidRequestException for an execution id never started, got {code!r}"
    )
    assert message == f"QueryExecution {missing_id} was not found", repr(message)


def _create_results_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-qrs-")
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
