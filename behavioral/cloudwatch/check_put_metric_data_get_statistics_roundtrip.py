"""put-metric-data-get-statistics-roundtrip."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "put-metric-data-get-statistics-roundtrip"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PutMetricData datapoint is retrievable via GetMetricStatistics with the
    exact Sum/SampleCount/Unit it was published with."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-ns-")
    metric_name = "OrdersProcessed"
    dim = {"Name": "Environment", "Value": "sim2real-test"}
    now = datetime.now(timezone.utc)

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric_name,
                "Dimensions": [dim],
                "Timestamp": now,
                "Value": 42.0,
                "Unit": "Count",
            }
        ],
    )

    def _stats():
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=[dim],
            StartTime=now - timedelta(minutes=5),
            EndTime=now + timedelta(minutes=5),
            Period=300,
            Statistics=["Sum", "SampleCount"],
        )
        return resp["Datapoints"]

    datapoints = _poll_until(_stats, lambda dp: len(dp) >= 1, timeout_s=120, interval_s=5)
    assert len(datapoints) == 1, f"expected exactly one aggregated datapoint, got {datapoints}"
    dp = datapoints[0]
    assert dp["Sum"] == 42.0, f"expected Sum 42.0, got {dp['Sum']}"
    assert dp["SampleCount"] == 1.0, f"expected SampleCount 1.0, got {dp['SampleCount']}"
    assert dp["Unit"] == "Count", f"expected Unit Count, got {dp['Unit']}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for condition; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
