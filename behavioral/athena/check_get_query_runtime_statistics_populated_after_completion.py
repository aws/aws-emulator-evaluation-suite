"""get-query-runtime-statistics-populated-after-completion."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-query-runtime-statistics-populated-after-completion"
GROUP = "state-machine"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetQueryRuntimeStatistics carries no output-row count while the query is
    still running, and full statistics (execution time, output rows) only once
    GetQueryExecution reports the terminal SUCCEEDED state."""
    athena = ctx.client("athena")
    bucket = _create_bucket(ctx)

    # A synthetic, non-S3-scanning query that is slow enough to likely still be
    # RUNNING by the time we immediately probe its runtime statistics. Presto/Trino's
    # SEQUENCE function caps out at 10,000 generated entries per call (a larger bound,
    # such as the previously used 20,000,000, is rejected outright), so a cross join of
    # two bounded sequences is used instead to generate a large-enough row count.
    query = (
        "SELECT COUNT(*) AS c FROM UNNEST(SEQUENCE(1, 9999)) AS a(n) "
        "CROSS JOIN UNNEST(SEQUENCE(1, 9999)) AS b(n)"
    )
    resp = athena.start_query_execution(
        QueryString=query, ResultConfiguration={"OutputLocation": f"s3://{bucket}/"}
    )
    qid = resp["QueryExecutionId"]

    # Wait out QUEUED so the probe below runs while the query is RUNNING: a query moves
    # QUEUED -> RUNNING -> terminal, so a refusal issued after RUNNING was read names RUNNING.
    pre_state = _poll_until(
        lambda: athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"],
        lambda s: s != "QUEUED",
        timeout_s=60,
        interval_s=0.25,
    )
    if pre_state == "RUNNING":
        try:
            pre_stats = athena.get_query_runtime_statistics(QueryExecutionId=qid)["QueryRuntimeStatistics"]
            pre_output_rows = pre_stats.get("Rows", {}).get("OutputRows")
            # Only a query still RUNNING after the read pins the read inside the running window.
            post_state = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
            if post_state == "RUNNING":
                assert pre_output_rows is None, (
                    f"expected no OutputRows before completion (state={pre_state}), got {pre_output_rows}"
                )
        except ClientError as e:
            assert e.response["Error"]["Code"] == "InvalidRequestException", (
                f"expected InvalidRequestException, got {e.response['Error']['Code']}"
            )
            message = e.response["Error"].get("Message")
            assert message == "Query has not yet finished. Current state: RUNNING", (
                f"unexpected GetQueryRuntimeStatistics message: {message!r}"
            )

    final_state = _poll_until(
        lambda: athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"],
        lambda s: s in ("SUCCEEDED", "FAILED", "CANCELLED"),
        timeout_s=180,
        interval_s=3,
    )
    assert final_state == "SUCCEEDED", f"query did not succeed, state={final_state}"

    stats = athena.get_query_runtime_statistics(QueryExecutionId=qid)["QueryRuntimeStatistics"]
    timeline = stats.get("Timeline", {})
    assert "TotalExecutionTimeInMillis" in timeline
    assert timeline["TotalExecutionTimeInMillis"] >= 0
    rows = stats.get("Rows", {})
    assert rows.get("OutputRows") == 1, f"expected exactly 1 output row for a COUNT query, got {rows.get('OutputRows')}"


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-athena-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "get-query-runtime-statistics-populated-after-completion"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})

    def _cleanup():
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
