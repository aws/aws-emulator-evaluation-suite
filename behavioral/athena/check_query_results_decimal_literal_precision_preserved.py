"""query-results-decimal-literal-precision-preserved."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "query-results-decimal-literal-precision-preserved"
GROUP = "representation"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """SELECT-ing a high-precision DECIMAL literal and reading it back via
    GetQueryResults preserves the exact decimal string representation, with no
    rounding or trailing-digit loss.
    """
    athena = ctx.client("athena")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-athena-dec-").replace("_", "-")
    _create_bucket(ctx, s3, bucket)
    prefix = "results/"

    # 24 integer digits + 9 fractional digits = 33 significant digits, within the
    # DECIMAL(38, 9) precision budget, so casting is lossless (no rounding needed).
    decimal_literal = "123456789012345678901234.123456789"
    query = f"SELECT CAST('{decimal_literal}' AS DECIMAL(38,9)) AS dec_val"

    exec_id = athena.start_query_execution(
        QueryString=query,
        ResultConfiguration={"OutputLocation": f"s3://{bucket}/{prefix}"},
    )["QueryExecutionId"]

    def _cleanup_query() -> None:
        # StopQueryExecution on a query that already finished succeeds as a no-op.
        athena.stop_query_execution(QueryExecutionId=exec_id)

    ctx.on_cleanup(_cleanup_query)

    state = _poll_until_terminal(athena, exec_id, timeout_s=90.0)
    assert state == "SUCCEEDED", f"query did not succeed, ended in state {state!r}"

    result = athena.get_query_results(QueryExecutionId=exec_id)
    rows = result["ResultSet"]["Rows"]
    assert len(rows) == 2, f"expected header row + 1 data row, got {len(rows)} rows"
    header_value = rows[0]["Data"][0]["VarCharValue"]
    assert header_value == "dec_val", f"expected header 'dec_val', got {header_value!r}"
    data_value = rows[1]["Data"][0]["VarCharValue"]
    assert data_value == decimal_literal, (
        f"decimal round-trip mismatch:\nexpected={decimal_literal!r}\nactual={data_value!r}"
    )


def _create_bucket(ctx, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "query-results-decimal-literal-precision-preserved"},
    ]})

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)


def _poll_until_terminal(athena, exec_id: str, timeout_s: float = 90.0) -> str:
    deadline = time.monotonic() + timeout_s
    state = "QUEUED"
    while time.monotonic() < deadline:
        status = athena.get_query_execution(QueryExecutionId=exec_id)["QueryExecution"]["Status"]
        state = status["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            return state
        time.sleep(2)
    raise AssertionError(f"query execution did not reach a terminal state in {timeout_s}s (last={state})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
