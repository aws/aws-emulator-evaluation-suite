"""metric-data-long-term-retention-downsampling-boundary."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metric-data-long-term-retention-downsampling-boundary"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A StartTime more than 3 hours ago returns no datapoints at a sub-60s Period but the datum at
    60s, while a recent StartTime serves the same sub-60s Period: the documented tiering rule.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_GetMetricStatistics.html
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-cw-retention-")
    metric_name = "boundary-metric"
    value = 12345.0

    put_time = datetime.now(timezone.utc)
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric_name,
                "Timestamp": put_time,
                "Value": value,
                "Unit": "Count",
                "StorageResolution": 1,
            }
        ],
    )

    # The 3h tier is the only one reachable: PutMetricData rejects data older than two weeks, and
    # widening the query window avoids backdated data's ingestion delay. The window stays under the
    # 1440-datapoint cap at Period=10 (4h).
    wide_start = put_time - timedelta(hours=3, minutes=20)
    wide_end = put_time + timedelta(minutes=2)
    narrow_start = put_time - timedelta(minutes=2)
    narrow_end = put_time + timedelta(minutes=2)

    fine_old = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric_name,
        Dimensions=[],
        StartTime=wide_start,
        EndTime=wide_end,
        Period=10,
        Statistics=["Sum"],
    )
    assert fine_old["Datapoints"] == [], (
        "expected no datapoints for a >3h-old StartTime queried at a sub-60s "
        f"period, got {fine_old['Datapoints']}"
    )

    coarse_old = _poll_until(
        lambda: cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=[],
            StartTime=wide_start,
            EndTime=wide_end,
            Period=60,
            Statistics=["Sum", "SampleCount"],
        ),
        lambda resp: len(resp["Datapoints"]) == 1,
        timeout_s=60,
        interval_s=3,
    )
    assert len(coarse_old["Datapoints"]) == 1, (
        f"expected exactly 1 datapoint for the >3h-old StartTime at a 60s-multiple "
        f"period, got {coarse_old['Datapoints']}"
    )
    assert coarse_old["Datapoints"][0]["Sum"] == value, (
        f"expected Sum == {value}, got {coarse_old['Datapoints'][0]['Sum']}"
    )
    assert coarse_old["Datapoints"][0]["SampleCount"] == 1.0, (
        f"expected SampleCount == 1.0, got {coarse_old['Datapoints'][0]['SampleCount']}"
    )

    # Shows the empty result above was the tiering rule, not an inability to serve fine periods.
    fine_recent = _poll_until(
        lambda: cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=[],
            StartTime=narrow_start,
            EndTime=narrow_end,
            Period=10,
            Statistics=["Sum"],
        ),
        lambda resp: len(resp["Datapoints"]) == 1,
        timeout_s=60,
        interval_s=3,
    )
    assert len(fine_recent["Datapoints"]) == 1, (
        f"expected exactly 1 datapoint for a recent StartTime at a sub-60s period, "
        f"got {fine_recent['Datapoints']}"
    )
    assert fine_recent["Datapoints"][0]["Sum"] == value, (
        f"expected Sum == {value}, got {fine_recent['Datapoints'][0]['Sum']}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
