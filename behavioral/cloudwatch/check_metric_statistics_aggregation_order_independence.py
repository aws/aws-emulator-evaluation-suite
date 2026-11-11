"""metric-statistics-aggregation-order-independence."""
from __future__ import annotations

import datetime

from behavioral_harness import tags

CHECK = "metric-statistics-aggregation-order-independence"
GROUP = 'metric-data'
SERVICES = ['cloudwatch']

_NAMESPACE = "SimParityProbe/Behavioral"


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricStatistics produces the same aggregated statistics regardless
    of the order in which PutMetricData points were submitted."""
    cw = ctx.client("cloudwatch")
    values = [10.0, 20.0, 30.0, 40.0]
    period_s = (len(values) + 1) * 60
    # Aligned to a period boundary, so one period holds all the points whether a period is
    # counted from StartTime or from the epoch.
    start_s = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) - 20 * 60
    base = datetime.datetime.fromtimestamp(start_s - start_s % period_s, datetime.timezone.utc)
    timestamps = [base + datetime.timedelta(minutes=i) for i in range(len(values))]

    metric_ordered = ctx.unique_name("sim2real-behav-cwprobe-metric-ord-a-")
    metric_scrambled = ctx.unique_name("sim2real-behav-cwprobe-metric-ord-b-")

    # Group A: published strictly in temporal order.
    for ts, v in zip(timestamps, values):
        cw.put_metric_data(
            Namespace=_NAMESPACE,
            MetricData=[{"MetricName": metric_ordered, "Timestamp": ts, "Value": v}],
        )

    # Group B: identical (timestamp, value) pairs, scrambled submission order.
    scramble = [3, 0, 2, 1]
    for idx in scramble:
        cw.put_metric_data(
            Namespace=_NAMESPACE,
            MetricData=[
                {"MetricName": metric_scrambled, "Timestamp": timestamps[idx], "Value": values[idx]}
            ],
        )

    stats = ["Sum", "Average", "Minimum", "Maximum", "SampleCount"]

    def make_probe(metric_name):
        def probe():
            resp = cw.get_metric_statistics(
                Namespace=_NAMESPACE,
                MetricName=metric_name,
                StartTime=base,
                EndTime=base + datetime.timedelta(minutes=len(values) + 1),
                Period=period_s,
                Statistics=stats,
            )
            return resp.get("Datapoints", [])

        return probe

    dp_a = _poll_until(
        make_probe(metric_ordered), lambda dp: len(dp) > 0 and dp[0].get("SampleCount") == len(values),
        timeout_s=90, interval_s=3, description="ordered-submission metric statistics fully ingested",
    )[0]
    dp_b = _poll_until(
        make_probe(metric_scrambled), lambda dp: len(dp) > 0 and dp[0].get("SampleCount") == len(values),
        timeout_s=90, interval_s=3, description="scrambled-submission metric statistics fully ingested",
    )[0]

    for stat in stats:
        va, vb = dp_a[stat], dp_b[stat]
        assert abs(va - vb) < 1e-9, (
            f"{stat} must be identical regardless of submission order: ordered={va} scrambled={vb}"
        )
    assert abs(dp_a["Sum"] - sum(values)) < 1e-6, (
        f"expected Sum={sum(values)}, got {dp_a['Sum']}"
    )
    assert dp_a["SampleCount"] == len(values), (
        f"expected SampleCount={len(values)}, got {dp_a['SampleCount']}"
    )
    assert dp_a["Minimum"] == min(values), (
        f"expected Minimum={min(values)}, got {dp_a['Minimum']}"
    )
    assert dp_a["Maximum"] == max(values), (
        f"expected Maximum={max(values)}, got {dp_a['Maximum']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
