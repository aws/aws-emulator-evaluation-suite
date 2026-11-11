"""metric-data-statistics-roundtrip."""
from __future__ import annotations

import datetime as dt
import time

from behavioral_harness import tags

CHECK = "metric-data-statistics-roundtrip"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A single pre-aggregated StatisticValues summary round-trips through GetMetricStatistics
    exactly as submitted, including the Average that CloudWatch must derive as Sum/SampleCount
    rather than accept verbatim (StatisticValues carries no Average field)."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-cw-ns-")
    metric_name = "RoundtripMetric"
    ts = dt.datetime.now(dt.timezone.utc).replace(second=0, microsecond=0)
    statistic_values = {"SampleCount": 5, "Sum": 50.0, "Minimum": 5.0, "Maximum": 15.0}
    expected_average = statistic_values["Sum"] / statistic_values["SampleCount"]

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric_name,
                "Timestamp": ts,
                "StatisticValues": statistic_values,
                "Unit": "Count",
            }
        ],
    )

    datapoints = _poll_for_datapoints(
        ctx,
        cw,
        namespace=namespace,
        metric_name=metric_name,
        start=ts - dt.timedelta(minutes=1),
        end=ts + dt.timedelta(minutes=2),
        statistics=["Sum", "SampleCount", "Minimum", "Maximum", "Average"],
    )
    if not datapoints:
        raise AssertionError("metric datapoint did not land within the ingestion poll window")

    dp = datapoints[0]
    assert dp["Sum"] == statistic_values["Sum"], f"Sum: expected {statistic_values['Sum']!r}, got {dp['Sum']!r}"
    assert dp["SampleCount"] == float(statistic_values["SampleCount"]), (
        f"SampleCount: expected {float(statistic_values['SampleCount'])!r}, got {dp['SampleCount']!r}"
    )
    assert dp["Minimum"] == statistic_values["Minimum"], (
        f"Minimum: expected {statistic_values['Minimum']!r}, got {dp['Minimum']!r}"
    )
    assert dp["Maximum"] == statistic_values["Maximum"], (
        f"Maximum: expected {statistic_values['Maximum']!r}, got {dp['Maximum']!r}"
    )
    assert abs(dp["Average"] - expected_average) < 1e-9, (
        f"Average: expected the derived {expected_average!r} (Sum/SampleCount), got {dp['Average']!r}"
    )
    assert dp["Unit"] == "Count", f"Unit: expected 'Count', got {dp['Unit']!r}"


# ===== helpers =====
def _poll_for_datapoints(ctx, cw, *, namespace, metric_name, start, end, statistics, timeout_s=180.0, interval_s=2.0):
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    while time.monotonic() < deadline:
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=start,
            EndTime=end,
            Period=60,
            Statistics=statistics,
        )
        if resp["Datapoints"]:
            return resp["Datapoints"]
        time.sleep(interval_s)
    return []


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
