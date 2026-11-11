"""metric-data-sub-minute-resolution-3-hour-expiry-boundary."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metric-data-sub-minute-resolution-3-hour-expiry-boundary"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A high-resolution point is readable at Period=1; a 4-hour Period=1 query exceeds the cap.

    The over-cap query is InvalidParameterCombination with the exact 1,440-datapoint message,
    while the same range at Period=3600 returns the point's value.
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-hires-ns-")
    metric_name = "QueueDepth"
    dim_value = ctx.unique_name("dim-")
    dimensions = [{"Name": "Case", "Value": dim_value}]

    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    ts = now - datetime.timedelta(seconds=10)

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{
            "MetricName": metric_name,
            "Dimensions": dimensions,
            "Timestamp": ts,
            "Value": 111.0,
            "Unit": "Count",
            "StorageResolution": 1,
        }],
    )

    def _query(period, start, end):
        return cw.get_metric_statistics(
            Namespace=namespace, MetricName=metric_name, Dimensions=dimensions,
            StartTime=start, EndTime=end, Period=period, Statistics=["Average"],
        )["Datapoints"]

    # Within the 3-hour window, sub-minute granularity sees the fresh point.
    inside_window = _poll_until(
        lambda: _query(1, now - datetime.timedelta(minutes=2), now + datetime.timedelta(minutes=1)),
        lambda pts: len(pts) > 0,
        timeout_s=60,
        interval_s=3,
    )
    assert any(abs(p["Average"] - 111.0) < 0.01 for p in inside_window), (
        f"expected a datapoint averaging 111.0 inside the fresh sub-minute window, got {inside_window!r}"
    )

    # A wide range (>4h) at a sub-minute Period requires far more than the
    # 1,440-datapoint cap that bounds the high-resolution (3h) retention tier, so
    # CloudWatch rejects the request outright rather than silently truncating or
    # returning partial/empty results.
    try:
        rows = _query(1, now - datetime.timedelta(hours=4), now + datetime.timedelta(minutes=1))
    except ClientError as exc:
        error = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
    else:
        raise AssertionError(f"expected the over-cap query to be rejected, but it returned {rows!r}")
    assert error == ("InvalidParameterCombination", (
        "You have requested up to 14460 datapoints, which exceeds the limit of 1440. You may "
        "reduce the datapoints requested by increasing Period, or decreasing the time range."
    )), (
        f"expected the InvalidParameterCombination rejection for a sub-minute-Period query spanning "
        f"beyond the high-resolution retention tier, got {error!r}"
    )

    # The exact same wide range remains queryable at the 1-hour rollup resolution,
    # which stays well under the datapoint cap (5 hourly buckets).
    hour_start = (now - datetime.timedelta(hours=4)).replace(minute=0, second=0)
    coarse = _poll_until(
        lambda: _query(3600, hour_start, now + datetime.timedelta(hours=1)),
        lambda pts: len(pts) > 0,
        timeout_s=60,
        interval_s=3,
    )
    assert any(abs(p["Average"] - 111.0) < 0.01 for p in coarse), (
        f"expected the same wide range queryable at the 1-hour rollup resolution "
        f"to average 111.0, got {coarse!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
