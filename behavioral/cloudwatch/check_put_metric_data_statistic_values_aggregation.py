"""put-metric-data-statistic-values-aggregation."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "put-metric-data-statistic-values-aggregation"
GROUP = 'metric-data'
SERVICES = ['cloudwatch']

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutMetricData accepts pre-aggregated StatisticValues and reports them verbatim."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-cwprobe-ns-")
    metric_name = "Latency"
    now = datetime.now(timezone.utc).replace(microsecond=0)

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric_name,
                "Timestamp": now,
                "StatisticValues": {
                    "SampleCount": 5,
                    "Sum": 50.0,
                    "Minimum": 5.0,
                    "Maximum": 15.0,
                },
                "Unit": "Milliseconds",
            }
        ],
    )

    def probe():
        return cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=now - timedelta(minutes=5),
            EndTime=now + timedelta(minutes=5),
            Period=300,
            Statistics=["Sum", "SampleCount", "Minimum", "Maximum"],
        )

    resp = _poll_until(probe, lambda r: len(r.get("Datapoints", [])) > 0, timeout_s=30, interval_s=2)
    dp = resp["Datapoints"][0]
    assert dp["Sum"] == 50.0, f"expected Sum=50.0, got {dp['Sum']!r}"
    assert dp["SampleCount"] == 5.0, f"expected SampleCount=5.0, got {dp['SampleCount']!r}"
    assert dp["Minimum"] == 5.0, f"expected Minimum=5.0, got {dp['Minimum']!r}"
    assert dp["Maximum"] == 15.0, f"expected Maximum=15.0, got {dp['Maximum']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
