"""get-metric-statistics-too-many-datapoints-rejected."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-metric-statistics-too-many-datapoints-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricStatistics enforces the documented 1440-datapoint quota: querying
    a 10-day window at a 60s period would yield ~14,400 datapoints, which must be
    rejected rather than silently truncated or fully computed."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-ns-")
    metric_name = "OverQuotaMetric"
    now = datetime.now(timezone.utc)

    # Positive control: the identical namespace/metric/period, windowed to stay
    # under the 1,440-datapoint cap, must succeed. Without this, a target that
    # rejects every GetMetricStatistics call would pass the check below for the
    # wrong reason.
    control = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric_name,
        StartTime=now - timedelta(hours=1),
        EndTime=now,
        Period=60,
        Statistics=["Average"],
    )
    assert "Datapoints" in control, (
        f"positive control: an in-quota GetMetricStatistics call must succeed, got {control!r}"
    )

    code, message = _error_code(
        lambda: cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=now - timedelta(days=10),
            EndTime=now,
            Period=60,
            Statistics=["Average"],
        )
    )
    assert code == "InvalidParameterCombination", (
        f"expected InvalidParameterCombination for a >1440-datapoint request, got {code}"
    )
    expected = (
        "You have requested up to 14400 datapoints, which exceeds the limit of 1440. "
        "You may reduce the datapoints requested by increasing Period, or decreasing the time range."
    )
    assert message == expected, f"expected the exact message {expected!r}, got {message!r}"


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). A SUCCESS raises AssertionError."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
