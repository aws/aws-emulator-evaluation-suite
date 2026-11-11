"""get-metric-statistics-highres-retention-boundary-empty."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "get-metric-statistics-highres-retention-boundary-empty"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricStatistics filters by [StartTime, EndTime): a Period=1 query over a recent window returns
    the published high-resolution datapoint (Sum 42.0), while the same query over a window 3 hours
    before the metric's only publish returns an empty Datapoints list."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-highres-ns-")
    metric_name = "HighResMetric"
    value = 42.0
    now = datetime.now(timezone.utc).replace(microsecond=0)

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric_name,
                "Timestamp": now,
                "Value": value,
                "Unit": "Count",
                "StorageResolution": 1,
            }
        ],
    )

    def _recent_datapoints() -> list[dict[str, Any]]:
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=now - timedelta(minutes=2),
            EndTime=now + timedelta(minutes=2),
            Period=1,
            Statistics=["Sum"],
        )
        return resp["Datapoints"]

    # Positive control: the high-res datapoint we just wrote is retrievable at sub-minute
    # granularity for a recent window.
    recent = _poll_until(_recent_datapoints, lambda dps: len(dps) > 0, timeout_s=120, interval_s=5)
    assert len(recent) > 0, (
        f"expected the freshly published high-res datapoint visible at sub-minute granularity "
        f"in a recent window, got {recent!r}"
    )
    assert any(abs(dp["Sum"] - value) < 1e-6 for dp in recent), (
        f"expected the recent-window datapoint to carry the published value {value}, got {recent!r}"
    )

    # Boundary: a window entirely before this namespace/metric ever existed -- no data was
    # ever published there and none can exist -- at the SAME sub-minute Period as the
    # positive control above, so a target that ignores StartTime/EndTime filtering (returning
    # whatever it has for the metric regardless of the requested window) fails here.
    past_start = now - timedelta(hours=3, minutes=10)
    past_end = now - timedelta(hours=3, minutes=5)
    resp = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric_name,
        StartTime=past_start,
        EndTime=past_end,
        Period=1,
        Statistics=["Sum"],
    )
    assert resp["Datapoints"] == [], (
        f"expected empty Datapoints for a window [{past_start.isoformat()}, "
        f"{past_end.isoformat()}) that predates this metric's only publish at "
        f"{now.isoformat()}, got {resp['Datapoints']}"
    )


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
