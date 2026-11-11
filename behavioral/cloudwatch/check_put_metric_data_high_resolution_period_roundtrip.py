"""put-metric-data-high-resolution-period-roundtrip."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "put-metric-data-high-resolution-period-roundtrip"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """Three StorageResolution=1 datapoints published 20 s apart in one minute read back at
    Period=10 as at least three distinct datapoints with the published total Sum: only the count
    shows the high-resolution tier is kept rather than coalesced into one 60 s bucket."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-ns-")
    metric_name = "HighResEvents"
    base = datetime.now(timezone.utc).replace(microsecond=0)
    values = [2.0, 3.0, 5.0]
    offsets = [0, 20, 40]

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric_name,
                "Timestamp": base + timedelta(seconds=offset),
                "Value": value,
                "Unit": "Count",
                "StorageResolution": 1,
            }
            for value, offset in zip(values, offsets)
        ],
    )

    def _stats():
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=base - timedelta(seconds=10),
            EndTime=base + timedelta(seconds=50),
            Period=10,
            Statistics=["Sum"],
        )
        return resp["Datapoints"]

    datapoints = _poll_until(_stats, lambda dp: len(dp) >= 3, timeout_s=90, interval_s=3)
    assert len(datapoints) >= 3, (
        f"expected 3 distinct sub-minute datapoints (fine-grained storage honored), "
        f"got {len(datapoints)}: {datapoints}"
    )
    total = sum(dp["Sum"] for dp in datapoints)
    expected_total = sum(values)
    assert total == expected_total, (
        f"expected total Sum {expected_total} across high-res datapoints, got {total} ({datapoints})"
    )


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
