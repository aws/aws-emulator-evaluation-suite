"""get-metric-data-invalid-scan-by-value-rejected."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-metric-data-invalid-scan-by-value-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricData rejects an out-of-enum ScanBy with the exact platform ValidationError,
    while the identical query with ScanBy=TimestampAscending succeeds."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-cw-scanby-")
    metric_name = "RequestCount"
    now = datetime.now(timezone.utc)
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": metric_name, "Value": 3.0, "Timestamp": now}],
    )
    query = [
        {
            "Id": "m1",
            "MetricStat": {
                "Metric": {"Namespace": namespace, "MetricName": metric_name},
                "Period": 60,
                "Stat": "Sum",
            },
            "ReturnData": True,
        }
    ]
    start = now - timedelta(minutes=10)
    end = now + timedelta(minutes=10)

    # ScanBy is not a modeled CloudWatch error, so it surfaces as the common ValidationError.
    code, message = _error_code(
        lambda: cw.get_metric_data(
            MetricDataQueries=query, StartTime=start, EndTime=end, ScanBy="NotAValidScanByValue"
        )
    )
    assert code == "ValidationError", f"expected ValidationError for an out-of-enum ScanBy, got {code!r}"
    expected = (
        "1 validation error detected: Value at 'scanBy' failed to satisfy constraint: "
        "Member must satisfy enum value set: [TimestampAscending, TimestampDescending]"
    )
    assert message == expected, f"expected the exact message {expected!r}, got {message!r}"

    resp = cw.get_metric_data(
        MetricDataQueries=query, StartTime=start, EndTime=end, ScanBy="TimestampAscending"
    )
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected the identical query with an in-enum ScanBy to succeed, got HTTP {status}"
    result_id = resp["MetricDataResults"][0]["Id"]
    assert result_id == "m1", f"expected the query id to round-trip as 'm1', got {result_id!r}"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected GetMetricData to reject the invalid ScanBy, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
