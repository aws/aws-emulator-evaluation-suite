"""put-metric-data-get-metric-statistics-roundtrip."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "put-metric-data-get-metric-statistics-roundtrip"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """Values written via PutMetricData are aggregated correctly and retrievable via
    GetMetricStatistics (Sum/SampleCount/Average over the covering period)."""

    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealBehav")
    metric = "RoundtripMetric"
    now = datetime.now(timezone.utc).replace(microsecond=0)
    values = [3.0, 5.0, 7.0]

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {"MetricName": metric, "Timestamp": now, "Value": v, "Unit": "Count"}
            for v in values
        ],
    )

    def probe():
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric,
            StartTime=now - timedelta(minutes=5),
            EndTime=now + timedelta(minutes=5),
            Period=300,
            Statistics=["Sum", "SampleCount", "Average"],
        )
        return resp["Datapoints"]

    datapoints = _poll_until(probe, lambda dp: len(dp) > 0, timeout_s=180.0, interval_s=10.0)

    dp = datapoints[0]
    expected_sum = sum(values)
    assert abs(dp["Sum"] - expected_sum) < 1e-6, f"expected Sum={expected_sum}, got {dp['Sum']}"
    assert int(dp["SampleCount"]) == len(values), f"expected SampleCount={len(values)}, got {dp['SampleCount']}"
    expected_avg = expected_sum / len(values)
    assert abs(dp["Average"] - expected_avg) < 1e-6, f"expected Average={expected_avg}, got {dp['Average']}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
