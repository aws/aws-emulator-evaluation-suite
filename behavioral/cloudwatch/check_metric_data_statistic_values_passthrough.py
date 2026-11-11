"""metric-data-statistic-values-passthrough."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metric-data-statistic-values-passthrough"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Publishing a pre-aggregated StatisticValues set (instead of a raw Value) is stored as-is:
    querying it back with GetMetricStatistics returns exactly the Sum/Min/Max/SampleCount that
    were supplied, not a re-derived approximation."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealBehav/")
    metric_name = "StatSetTest"

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric_name,
                "StatisticValues": {
                    "SampleCount": 4.0,
                    "Sum": 100.0,
                    "Minimum": 10.0,
                    "Maximum": 40.0,
                },
                "Unit": "Count",
            }
        ],
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
            Statistics=["Sum", "SampleCount", "Minimum", "Maximum"],
        )["Datapoints"]

    left = ctx.time_left()
    deadline = time.monotonic() + (180.0 if left is None else min(180.0, left))
    datapoints: list = []
    while time.monotonic() < deadline:
        datapoints = probe()
        if datapoints:
            break
        time.sleep(2)

    if not datapoints:
        raise AssertionError(
            "statistic-set datapoint did not become queryable within the poll budget",
        )

    dp = datapoints[0]
    assert dp["SampleCount"] == 4.0, f"expected SampleCount=4.0, got {dp['SampleCount']!r}"
    assert dp["Sum"] == 100.0, f"expected Sum=100.0, got {dp['Sum']!r}"
    assert dp["Minimum"] == 10.0, f"expected Minimum=10.0, got {dp['Minimum']!r}"
    assert dp["Maximum"] == 40.0, f"expected Maximum=40.0, got {dp['Maximum']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
