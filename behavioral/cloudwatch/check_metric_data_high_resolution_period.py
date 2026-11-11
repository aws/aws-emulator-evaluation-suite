"""metric-data-high-resolution-period."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metric-data-high-resolution-period"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A datum published with StorageResolution=1 is returned at Period=1 (Sum 42.0), while a twin datum at
    standard resolution returns no Period=1 datapoint and is returned at Period=60 (Sum 42.0)."""

    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealBehav")
    metric = "HighResMetric"
    std_metric = "StdResMetric"
    now = datetime.now(timezone.utc).replace(microsecond=0)

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric,
                "Timestamp": now,
                "Value": 42.0,
                "Unit": "Count",
                "StorageResolution": 1,
            },
            {
                # No StorageResolution: defaults to standard (60s) resolution. Same
                # namespace, same instant, same query shape as the high-res datum above —
                # the only variable is the storage class under test.
                "MetricName": std_metric,
                "Timestamp": now,
                "Value": 42.0,
                "Unit": "Count",
            },
        ],
    )

    def probe_high_res():
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric,
            StartTime=now - timedelta(seconds=30),
            EndTime=now + timedelta(seconds=30),
            Period=1,
            Statistics=["Sum"],
        )
        return resp["Datapoints"]

    datapoints = _poll_until(probe_high_res, lambda dp: len(dp) > 0, timeout_s=120.0, interval_s=5.0)
    if not datapoints:
        raise AssertionError("high-resolution metric data did not land within the polling window")

    assert abs(datapoints[0]["Sum"] - 42.0) < 1e-6, datapoints

    std_datapoints = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=std_metric,
        StartTime=now - timedelta(seconds=30),
        EndTime=now + timedelta(seconds=30),
        Period=1,
        Statistics=["Sum"],
    )["Datapoints"]
    assert std_datapoints == [], (
        "a standard-resolution (60s) datum must not produce a sub-minute (Period=1) "
        f"datapoint the way the high-resolution twin did, got {std_datapoints}"
    )

    std_60s = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=std_metric,
        StartTime=now - timedelta(seconds=90),
        EndTime=now + timedelta(seconds=90),
        Period=60,
        Statistics=["Sum"],
    )["Datapoints"]
    assert std_60s and abs(std_60s[0]["Sum"] - 42.0) < 1e-6, (
        f"standard-resolution datum should still be retrievable at its native 60s "
        f"period, got {std_60s}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
