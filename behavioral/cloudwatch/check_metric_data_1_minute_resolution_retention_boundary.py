"""metric-data-1-minute-resolution-retention-boundary."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metric-data-1-minute-resolution-retention-boundary"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricStatistics at Period=60 returns a fresh datapoint (Average 333.0) over a 5-minute window,
    rejects the same Period over 14 days (20161 datapoints, over the 1440 cap) with
    InvalidParameterCombination and its exact message, and returns the datapoint at Period=3600 over 14 days."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-retention-ns-")
    metric_name = "StandardResMetric"
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
            "Value": 333.0,
            "Unit": "Count",
        }],
    )

    def _query(period, start, end):
        return cw.get_metric_statistics(
            Namespace=namespace, MetricName=metric_name, Dimensions=dimensions,
            StartTime=start, EndTime=end, Period=period, Statistics=["Average"],
        )["Datapoints"]

    end_time = now + datetime.timedelta(minutes=1)

    # A narrow recent window at 1-minute resolution stays well within the cap and
    # returns the fresh point.
    narrow = _poll_until(
        lambda: _query(60, now - datetime.timedelta(minutes=5), end_time),
        lambda pts: len(pts) > 0,
        timeout_s=60,
        interval_s=3,
    )
    assert any(abs(p["Average"] - 333.0) < 0.01 for p in narrow), (
        f"expected an Average of 333.0 in the narrow 1-minute-resolution window, got {narrow!r}"
    )

    # A 14-day-wide query at the same 60-second Period would require ~20,160
    # datapoints -- far beyond the 1,440-datapoint cap that bounds how much
    # 1-minute-resolution history a single call can retrieve -- so CloudWatch
    # rejects it outright rather than silently truncating.
    try:
        rows = _query(60, now - datetime.timedelta(days=14), end_time)
    except ClientError as exc:
        error = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
    else:
        raise AssertionError(f"expected the over-cap query to be rejected, but it returned {rows!r}")
    assert error == ("InvalidParameterCombination", (
        "You have requested up to 20161 datapoints, which exceeds the limit of 1440. You may "
        "reduce the datapoints requested by increasing Period, or decreasing the time range."
    )), (
        f"expected the InvalidParameterCombination rejection for a 60s-Period query spanning "
        f"14 days, got {error!r}"
    )

    # The identical 14-day-wide range is queryable at the 1-hour rollup Period
    # (336 datapoints), which is the resolution 1-minute data ages into once it
    # leaves the 15-day standard-resolution tier.
    coarse = _poll_until(
        lambda: _query(3600, now - datetime.timedelta(days=14), end_time),
        lambda pts: len(pts) > 0,
        timeout_s=60,
        interval_s=3,
    )
    assert any(abs(p["Average"] - 333.0) < 0.01 for p in coarse), (
        f"expected an Average of 333.0 in the 14-day-wide 1-hour-rollup window, got {coarse!r}"
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
