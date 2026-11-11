"""metric-data-high-resolution-storage-resolution."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metric-data-high-resolution-storage-resolution"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A datapoint published with StorageResolution=1 (high resolution) is retrievable at
    a sub-minute Period under its native 10s bucket, while a standard-resolution datapoint
    published at the same instant is coalesced to the containing 60s bucket."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealBehavioral-")
    metric_name = "HighResValue"
    std_metric_name = "StdResValue"
    ts = datetime.now(timezone.utc).replace(microsecond=0)
    # Outside a minute's first 10s the 10s bucket and the whole-minute bucket differ, so the two
    # storage classes are told apart whatever the clock reads.
    if ts.second < 10:
        ts -= timedelta(seconds=15)

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric_name,
                "Timestamp": ts,
                "Value": 42.0,
                "Unit": "Count",
                "StorageResolution": 1,
            },
            {
                # No StorageResolution -> standard (60s) resolution. Same value, same
                # timestamp, same namespace -- the only variable is the storage class.
                "MetricName": std_metric_name,
                "Timestamp": ts,
                "Value": 42.0,
                "Unit": "Count",
            },
        ],
    )

    datapoints = _poll_datapoints(
        ctx, namespace, metric_name, ts - timedelta(seconds=30), ts + timedelta(seconds=30)
    )
    if not datapoints:
        raise AssertionError(
            "high-resolution datapoint never became queryable within timeout",
        )

    assert datapoints[0]["Sum"] == 42.0, f"expected Sum=42.0 at 10s resolution, got {datapoints[0]['Sum']}"

    # A period-10 query is syntactically legal against ANY metric (AWS enumerates accepted
    # sub-minute Period values without checking the metric's own storage class), so
    # presence/absence of a datapoint cannot tell high from standard resolution -- both
    # eventually answer. What varies is the BUCKET the datapoint is reported under: a
    # standard-resolution metric queried with Period=10 still returns one datapoint, but its
    # Timestamp is coalesced to the containing 60s (whole-minute) boundary, discarding the
    # sub-minute publish instant. A high-resolution metric preserves the 10s bucket the
    # publish instant actually falls in. That bucketing difference -- not mere queryability
    # -- is what "honors storage resolution rather than always coalescing to 60s buckets"
    # means, and it is what an emulator that ignores StorageResolution (and just answers any
    # Period from whatever granularity it stored) fails to reproduce.
    expected_hires_bucket = ts - timedelta(seconds=ts.second % 10)
    assert datapoints[0]["Timestamp"] == expected_hires_bucket, (
        f"high-resolution datapoint reported under Timestamp={datapoints[0]['Timestamp']!r}, "
        f"expected the 10s-aligned bucket {expected_hires_bucket!r} containing the publish "
        f"instant {ts!r}"
    )

    # The window is aligned to the whole minute, so it holds the 60s bucket whatever the publish second.
    minute = ts.replace(second=0)
    std_datapoints = _poll_datapoints(
        ctx, namespace, std_metric_name, minute - timedelta(seconds=60), minute + timedelta(seconds=60)
    )
    if not std_datapoints:
        raise AssertionError(
            "standard-resolution datapoint never became queryable at Period=10 within timeout",
        )
    assert len(std_datapoints) == 1, (
        f"expected exactly one coalesced datapoint for the standard-resolution metric, "
        f"got {std_datapoints}"
    )
    assert std_datapoints[0]["Sum"] == 42.0, (
        f"expected Sum=42.0 for the standard-resolution metric, got {std_datapoints[0]['Sum']}"
    )
    expected_std_bucket = minute
    assert std_datapoints[0]["Timestamp"] == expected_std_bucket, (
        f"standard-resolution datapoint reported under Timestamp={std_datapoints[0]['Timestamp']!r}, "
        f"expected the whole-minute bucket {expected_std_bucket!r}; reporting it under the "
        f"high-resolution bucket means the emulator is not distinguishing storage resolution"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_datapoints(ctx, namespace: str, metric_name: str, start, end, timeout_s: float = 120.0):
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while time.monotonic() < deadline:
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=start,
            EndTime=end,
            Period=10,
            Statistics=["Sum"],
        )
        if resp["Datapoints"]:
            return resp["Datapoints"]
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"{metric_name} datapoints becoming queryable: the run budget ended first; not graded")
    return []


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
