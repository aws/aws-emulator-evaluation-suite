"""put-metric-data-get-statistics-exact-aggregation."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-metric-data-get-statistics-exact-aggregation"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """Three PutMetricData points in the same period aggregate to the exact Sum/SampleCount/Average."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealAgg")
    metric_name = "OrderValue"
    now = time.time()
    bucket_start = int(now - (now % 60)) - 120  # a settled period, 2 minutes in the past
    ts = bucket_start + 30

    for value in (10.0, 20.0, 30.0):
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": metric_name,
                    "Timestamp": ts,
                    "Value": value,
                    "Unit": "None",
                }
            ],
        )

    stats = _wait_for_statistics(
        cw,
        namespace,
        metric_name,
        start=bucket_start,
        end=bucket_start + 60,
        timeout_s=90.0,
    )
    assert stats is not None, "metric statistics never landed within timeout"
    assert stats["SampleCount"] == 3.0, f"expected SampleCount=3.0, got {stats['SampleCount']} ({stats})"
    assert stats["Sum"] == 60.0, f"expected Sum=60.0, got {stats['Sum']} ({stats})"
    assert stats["Average"] == 20.0, f"expected Average=20.0, got {stats['Average']} ({stats})"


def _wait_for_statistics(cw, namespace, metric_name, start, end, timeout_s=90.0, interval_s=3.0):
    import datetime

    deadline = time.monotonic() + timeout_s
    start_dt = datetime.datetime.fromtimestamp(start, tz=datetime.timezone.utc)
    end_dt = datetime.datetime.fromtimestamp(end, tz=datetime.timezone.utc)
    while time.monotonic() < deadline:
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=start_dt,
            EndTime=end_dt,
            Period=60,
            Statistics=["Sum", "SampleCount", "Average"],
        )
        datapoints = resp["Datapoints"]
        if datapoints:
            return datapoints[0]
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
