"""query-results-numeric-precision-preserved."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "query-results-numeric-precision-preserved"
GROUP = "representation"
SERVICES = ["athena"]


def _create_results_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-res-")
    # us-east-1 is the one region S3 rejects a LocationConstraint for.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            s3.delete_objects(
                Bucket=bucket,
                Delete={"Objects": [{"Key": o["Key"]} for o in objs]},
            )
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={
            "TagSet": [
                {"Key": "sim2real", "Value": "query-results-numeric-precision-preserved"},
                {"Key": "sim2real:managed", "Value": "true"},
            ]
        },
    )
    return bucket


def _wait_for_query(ctx, query_execution_id: str, timeout_s: float = 60.0) -> str:
    athena = ctx.client("athena")
    deadline = time.monotonic() + timeout_s
    state = "QUEUED"
    while time.monotonic() < deadline:
        state = athena.get_query_execution(QueryExecutionId=query_execution_id)["QueryExecution"][
            "Status"
        ]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            return state
        time.sleep(1.5)
    raise AssertionError(f"query {query_execution_id} did not reach a terminal state in {timeout_s}s")


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetQueryResults preserves full numeric precision of decimal/double literals exactly."""
    athena = ctx.client("athena")
    bucket = _create_results_bucket(ctx)

    decimal_literal = "1234567890123456789012345678.123456789"  # DECIMAL(38,9)
    query = (
        f"SELECT CAST('{decimal_literal}' AS DECIMAL(38,9)) AS precise_decimal, "
        f"CAST(3.141592653589793 AS DOUBLE) AS precise_double"
    )
    start = athena.start_query_execution(
        QueryString=query,
        ResultConfiguration={"OutputLocation": f"s3://{bucket}/out/"},
    )
    query_execution_id = start["QueryExecutionId"]
    state = _wait_for_query(ctx, query_execution_id)
    assert state == "SUCCEEDED", f"expected SUCCEEDED, got {state}"

    results = athena.get_query_results(QueryExecutionId=query_execution_id)
    rows = results["ResultSet"]["Rows"]
    # Row 0 is the column-header row for a SELECT statement; row 1 holds the actual values.
    assert len(rows) >= 2, f"expected a header row plus a data row, got {rows!r}"
    data_row = rows[1]["Data"]
    decimal_value = data_row[0]["VarCharValue"]
    double_value = data_row[1]["VarCharValue"]

    assert decimal_value == decimal_literal, (
        f"decimal precision not preserved: expected {decimal_literal!r}, got {decimal_value!r}"
    )
    assert double_value == "3.141592653589793", (
        f"double precision not preserved: expected '3.141592653589793', got {double_value!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
