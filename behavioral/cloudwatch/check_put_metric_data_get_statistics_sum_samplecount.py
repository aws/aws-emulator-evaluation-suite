"""put-metric-data-get-statistics-sum-samplecount."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "put-metric-data-get-statistics-sum-samplecount"
GROUP = 'metric-data'
SERVICES = ['cloudwatch']
POLL_BUDGET_S = 300.0  # poll budget for metric ingestion

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
    """PutMetricData with a plain Value is aggregated correctly by GetMetricStatistics."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-cwprobe-ns-")
    metric_name = "RequestCount"
    now = datetime.now(timezone.utc).replace(microsecond=0)

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {"MetricName": metric_name, "Timestamp": now, "Value": 4.0, "Unit": "Count"},
            {"MetricName": metric_name, "Timestamp": now, "Value": 6.0, "Unit": "Count"},
        ],
    )

    def probe():
        return cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=now - timedelta(minutes=5),
            EndTime=now + timedelta(minutes=5),
            Period=300,
            Statistics=["Sum", "SampleCount"],
        )

    resp = _poll_until(probe, lambda r: len(r.get("Datapoints", [])) > 0, timeout_s=POLL_BUDGET_S, interval_s=2)
    datapoints = resp["Datapoints"]
    assert len(datapoints) == 1, f"expected a single aggregated period, got {datapoints}"
    dp = datapoints[0]
    assert dp["Sum"] == 10.0, f"expected Sum=10.0, got {dp['Sum']}"
    assert dp["SampleCount"] == 2.0, f"expected SampleCount=2.0, got {dp['SampleCount']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
