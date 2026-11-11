"""metric-data-retention-window-enforced."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metric-data-retention-window-enforced"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricStatistics for a window far beyond CloudWatch's maximum retention
    (455 days, even at 1-hour resolution) returns no datapoints rather than fabricated
    data, while a freshly-published PutMetricData point in the current window is visible."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-retention/")
    metric_name = "RetentionProbe"

    now = datetime.now(timezone.utc)

    # 1) a window well beyond the maximum retention window (455 days at 1h resolution):
    #    no data was ever published there, and none can exist -> must be empty, not an error.
    old_start = now - timedelta(days=500)
    old_end = old_start + timedelta(hours=1)
    old_resp = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric_name,
        StartTime=old_start,
        EndTime=old_end,
        Period=3600,
        Statistics=["Average"],
    )
    assert old_resp["Datapoints"] == [], (
        f"expected no datapoints beyond retention window, got {old_resp['Datapoints']}"
    )

    # 2) publish fresh data now, and confirm it IS visible in a recent-window query
    value = 42.0
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": metric_name, "Value": value, "Unit": "Count"}],
    )

    recent_start = now - timedelta(minutes=5)
    recent_end = now + timedelta(minutes=2)
    datapoints = _poll_for_datapoints(
        cw, namespace, metric_name, recent_start, recent_end, timeout_s=90.0,
    )
    assert len(datapoints) >= 1, "freshly published metric data never became visible via GetMetricStatistics"
    assert any(abs(dp["Sum"] - value) < 1e-6 or abs(dp["Average"] - value) < 1e-6 for dp in datapoints), (
        f"published value {value} not reflected in recent-window datapoints: {datapoints}"
    )

    # 3) re-querying the ancient out-of-retention window is still empty (published data
    #    landed only in the recent window, confirming query scoping is not leaking).
    old_resp_again = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric_name,
        StartTime=old_start,
        EndTime=old_end,
        Period=3600,
        Statistics=["Average"],
    )
    assert old_resp_again["Datapoints"] == [], (
        f"old out-of-window query leaked newly published data: {old_resp_again['Datapoints']}"
    )


def _poll_for_datapoints(cw, namespace, metric_name, start, end, timeout_s=90.0):
    deadline = time.monotonic() + timeout_s
    datapoints = []
    while time.monotonic() < deadline:
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=start,
            EndTime=end,
            Period=60,
            Statistics=["Sum", "Average"],
        )
        datapoints = resp["Datapoints"]
        if datapoints:
            return datapoints
        time.sleep(5)
    raise AssertionError(
        "published metric data never appeared via GetMetricStatistics within timeout",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
