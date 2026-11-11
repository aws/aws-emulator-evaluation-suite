"""get-metric-statistics-sum-average-aggregation."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "get-metric-statistics-sum-average-aggregation"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """Three raw datapoints (10, 20, 30) published for the same metric/minute aggregate into a
    single GetMetricStatistics datapoint with Sum=60, Average=20, SampleCount=3."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealBehav/")
    metric_name = "AggregationTest"

    for value in (10.0, 20.0, 30.0):
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[{"MetricName": metric_name, "Value": value, "Unit": "Count"}],
        )

    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=5)
    end = now + timedelta(minutes=5)

    def probe():
        return cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=start,
            EndTime=end,
            Period=60,
            Statistics=["Sum", "Average", "SampleCount"],
        )["Datapoints"]

    left = ctx.time_left()
    deadline = time.monotonic() + (180.0 if left is None else min(180.0, left))
    datapoints: list = []
    while time.monotonic() < deadline:
        datapoints = probe()
        if datapoints and sum(d["SampleCount"] for d in datapoints) >= 3:
            break
        time.sleep(2.0)

    if not datapoints or sum(d["SampleCount"] for d in datapoints) < 3:
        raise AssertionError(
            "metric datapoints did not become queryable within the poll budget",
        )

    total_sum = sum(d["Sum"] for d in datapoints)
    total_count = sum(d["SampleCount"] for d in datapoints)
    assert total_count == 3, f"expected SampleCount=3, got {total_count}"
    assert abs(total_sum - 60.0) < 1e-6, f"expected Sum=60.0, got {total_sum}"
    weighted_avg = total_sum / total_count
    assert abs(weighted_avg - 20.0) < 1e-6, f"expected Average=20.0, got {weighted_avg}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
