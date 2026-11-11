"""get-query-runtime-statistics-reflects-execution-metrics."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-query-runtime-statistics-reflects-execution-metrics"
GROUP = "server-side"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """For a SUCCEEDED query, GetQueryRuntimeStatistics' Timeline sub-fields sum to a non-zero total
    and its engine time matches GetQueryExecution's Statistics."""
    athena = ctx.client("athena")
    s3 = ctx.client("s3")

    bucket_name = ctx.unique_name("sim2real-athena-qrs-").lower().replace("_", "-")
    # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _cleanup_bucket(s3, bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name,
        Tagging={
            "TagSet": [
                {"Key": "sim2real", "Value": "get-query-runtime-statistics-reflects-execution-metrics"},
                {"Key": "sim2real:managed", "Value": "true"},
            ]
        },
    )

    started = athena.start_query_execution(
        QueryString="SELECT 1 AS one",
        ResultConfiguration={"OutputLocation": f"s3://{bucket_name}/results/"},
    )
    query_execution_id = started["QueryExecutionId"]

    final = _poll_until(
        lambda: athena.get_query_execution(QueryExecutionId=query_execution_id)["QueryExecution"],
        lambda qe: qe["Status"]["State"] in ("SUCCEEDED", "FAILED", "CANCELLED"),
        timeout_s=120.0,
        interval_s=3.0,
    )
    assert final["Status"]["State"] == "SUCCEEDED", (
        f"expected the required terminal SUCCEEDED, got {final['Status']['State']!r}"
    )

    stats = athena.get_query_runtime_statistics(QueryExecutionId=query_execution_id)[
        "QueryRuntimeStatistics"
    ]
    timeline = stats["Timeline"]
    assert timeline["TotalExecutionTimeInMillis"] > 0, (
        f"a query that really ran must report a non-zero TotalExecutionTimeInMillis, got {timeline}"
    )
    # Timeline sub-fields are best-effort (a trivial SELECT omits QueryPlanningTimeInMillis), so
    # assert that whichever are present sum to the total.
    sub_fields = {k: v for k, v in timeline.items() if k != "TotalExecutionTimeInMillis"}
    computed_total = sum(sub_fields.values())
    assert computed_total == timeline["TotalExecutionTimeInMillis"], (
        f"Timeline sub-fields {sub_fields} sum to {computed_total}, expected this to equal "
        f"TotalExecutionTimeInMillis {timeline['TotalExecutionTimeInMillis']}"
    )

    # Both reads are of the same terminal, immutable execution record, so they agree exactly.
    engine_ms_from_timeline = timeline["EngineExecutionTimeInMillis"]
    engine_ms_from_exec = final["Statistics"]["EngineExecutionTimeInMillis"]
    assert engine_ms_from_timeline == engine_ms_from_exec, (
        f"GetQueryRuntimeStatistics EngineExecutionTimeInMillis ({engine_ms_from_timeline}) must "
        f"match GetQueryExecution Statistics EngineExecutionTimeInMillis ({engine_ms_from_exec})"
    )

    result_rows = athena.get_query_results(QueryExecutionId=query_execution_id)["ResultSet"]["Rows"]
    assert len(result_rows) == 2, (  # header row + the single data row
        f"expected header row + one data row, got {len(result_rows)} rows: {result_rows}"
    )
    assert result_rows[1]["Data"][0]["VarCharValue"] == "1", (
        f"expected the literal query to return '1', got {result_rows[1]['Data'][0]!r}"
    )


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    timeout_s: float = 300.0,
    interval_s: float = 10.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise TimeoutError(f"condition not met within {timeout_s}s; last={last!r}")


def _cleanup_bucket(s3: Any, bucket_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
