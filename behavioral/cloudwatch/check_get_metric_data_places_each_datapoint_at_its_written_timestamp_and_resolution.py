"""get-metric-data-places-each-datapoint-at-its-written-timestamp-and-resolution."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "get-metric-data-places-each-datapoint-at-its-written-timestamp-and-resolution"
GROUP = "metric-data"
SERVICES = ["cloudwatch"]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result) holds; raise on timeout (TimeoutError if the run budget ended it)."""
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended the wait. Last result: {last!r}")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _query(qid, namespace, metric_name, period, stat, **extra):
    return {
        "Id": qid,
        "MetricStat": {
            "Metric": {"Namespace": namespace, "MetricName": metric_name},
            "Period": period,
            "Stat": stat,
        },
        "ReturnData": True,
        **extra,
    }


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricData reports each datapoint at the timestamp and resolution it was written with:
    back-dated and future-dated points are readable now in their own buckets, and a high-resolution
    point keeps its second at Period=1 while a standard-resolution point reports its minute."""
    cw = ctx.client("cloudwatch")
    # A custom namespace cannot be deleted (no DeleteMetric API); it ages out.
    namespace = ctx.unique_name("sim2real-cw-gmd-axis-")
    minute = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    anchor = minute + timedelta(seconds=17)
    offsets = [timedelta(minutes=m) for m in (-60, -10, 30, 100)]

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            *({"MetricName": "Axis", "Timestamp": anchor + off, "Value": float(i)} for i, off in enumerate(offsets, 1)),
            {"MetricName": "MixRes", "Timestamp": minute + timedelta(seconds=2), "Value": 1.0},
            {"MetricName": "MixRes", "Timestamp": minute + timedelta(seconds=7), "Value": 2.0, "StorageResolution": 1},
        ],
    )

    def read(queries, start, end):
        resp = cw.get_metric_data(MetricDataQueries=queries, StartTime=start, EndTime=end, ScanBy="TimestampAscending")
        return {r["Id"]: r for r in resp["MetricDataResults"]}

    wide = [_query("axis", namespace, "Axis", 60, "Sum", Label="axis-label")]
    axis = _poll_until(
        ctx,
        lambda: read(wide, anchor - timedelta(minutes=90), anchor + timedelta(minutes=110))["axis"],
        lambda r: len(r["Values"]) == 4,
        timeout_s=60.0, description="all four back- and future-dated Axis points readable",
    )
    expected_stamps = [(anchor + off).replace(second=0) for off in offsets]
    assert axis["Timestamps"] == expected_stamps, (
        f"expected each point in the minute it was written for, {expected_stamps!r}, got {axis['Timestamps']!r}"
    )
    assert axis["Values"] == [1.0, 2.0, 3.0, 4.0], f"expected one value per bucket [1,2,3,4], got {axis['Values']!r}"
    assert axis["StatusCode"] == "Complete", f"expected StatusCode Complete, got {axis['StatusCode']!r}"
    assert axis["Label"] == "axis-label", f"expected the explicit Label to be echoed, got {axis.get('Label')!r}"

    future_bucket = expected_stamps[2]
    alone = read(wide[:1], future_bucket, future_bucket + timedelta(minutes=1))["axis"]
    assert (alone["Timestamps"], alone["Values"]) == ([future_bucket], [3.0]), (
        f"expected the future bucket alone to return [3.0] at {future_bucket!r}, "
        f"got {alone['Timestamps']!r} / {alone['Values']!r}"
    )

    no_data_start = minute + timedelta(hours=24)
    empty = read(wide[:1], no_data_start, no_data_start + timedelta(hours=1))["axis"]
    got = (empty["Timestamps"], empty["Values"], empty["StatusCode"])
    assert got == ([], [], "Complete"), (
        f"expected an empty Complete result for a future window that holds no data, got {got!r}"
    )

    per_second = _poll_until(
        ctx,
        lambda: read([_query("mix", namespace, "MixRes", 1, "Sum")], minute, minute + timedelta(seconds=60))["mix"],
        lambda r: len(r["Values"]) == 2,
        timeout_s=60.0, description="both MixRes points readable at Period=1",
    )
    hi_res = [minute, minute + timedelta(seconds=7)]
    assert per_second["Timestamps"] == hi_res, (
        f"expected the standard-resolution point at its minute and the high-resolution point at its "
        f"second, {hi_res!r}, got {per_second['Timestamps']!r}"
    )
    assert per_second["Values"] == [1.0, 2.0], f"expected Period=1 values [1,2], got {per_second['Values']!r}"

    merged = read(
        [_query("s", namespace, "MixRes", 60, "Sum"), _query("n", namespace, "MixRes", 60, "SampleCount")],
        minute, minute + timedelta(seconds=60),
    )
    got = (merged["s"]["Timestamps"], merged["s"]["Values"], merged["n"]["Values"])
    assert got == ([minute], [3.0], [2.0]), (
        f"expected both resolutions to share one Period=60 bucket (Sum 3, SampleCount 2) at {minute!r}, got {got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
