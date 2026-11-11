"""metric-data-put-get-statistics-round-trip."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metric-data-put-get-statistics-round-trip"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutMetricData followed by GetMetricStatistics returns Sum/SampleCount/Average
    that correctly aggregate the exact points that were published."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealBehavioral-")
    metric_name = "RoundTripValue"
    ts = datetime.now(timezone.utc).replace(microsecond=0)

    for _ in range(5):
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[{"MetricName": metric_name, "Timestamp": ts, "Value": 10.0, "Unit": "Count"}],
        )

    datapoints = _poll_datapoints(ctx, namespace, metric_name, ts)
    if not datapoints:
        raise AssertionError(
            "metric data never became queryable via GetMetricStatistics within timeout",
        )

    dp = datapoints[0]
    assert dp["Sum"] == 50.0, f"expected Sum=50.0, got {dp['Sum']}"
    assert dp["SampleCount"] == 5.0, f"expected SampleCount=5.0, got {dp['SampleCount']}"
    assert dp["Average"] == 10.0, f"expected Average=10.0, got {dp['Average']}"


def _poll_datapoints(ctx, namespace: str, metric_name: str, ts, timeout_s: float = 120.0, interval_s: float = 5.0):
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=ts - timedelta(minutes=5),
            EndTime=ts + timedelta(minutes=5),
            Period=300,
            Statistics=["Sum", "SampleCount", "Average"],
        )
        if resp["Datapoints"]:
            return resp["Datapoints"]
        time.sleep(interval_s)
    return []


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
