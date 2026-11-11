"""put-metric-data-separate-calls-sum-and-samplecount-per-minute-bucket."""
from __future__ import annotations

import random
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "put-metric-data-separate-calls-sum-and-samplecount-per-minute-bucket"
GROUP = 'metric-data'
SERVICES = ['cloudwatch']
POLL_BUDGET_S = 40.0  # a wait never exceeds 40 s; AWS answers well inside it


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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """Datapoints sent one per PutMetricData call, with random values spread over two minutes, are
    aggregated per 60 s period: each bucket's Sum and SampleCount equal the totals of its own values."""
    rng = random.SystemRandom()
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-cwbucket-ns-")
    metric_name = "QueueDepth"
    first = (datetime.now(timezone.utc) - timedelta(minutes=6)).replace(second=0, microsecond=0)
    minutes = [first, first + timedelta(minutes=1)]

    expected = {}
    datums = []
    for minute in minutes:
        values = [float(rng.randint(1, 500)) for _ in range(rng.randint(2, 5))]
        expected[minute] = (sum(values), float(len(values)))
        for v in values:
            datums.append({
                "MetricName": metric_name,
                "Timestamp": minute + timedelta(seconds=rng.randint(0, 59)),
                "Value": v,
                "Unit": "Count",
            })
    rng.shuffle(datums)
    for datum in datums:
        cw.put_metric_data(Namespace=namespace, MetricData=[datum])
    total = float(len(datums))

    def probe():
        return cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=first,
            EndTime=first + timedelta(minutes=2),
            Period=60,
            Statistics=["Sum", "SampleCount"],
        )

    # All datums are ingested once the per-bucket SampleCounts add up to what was sent.
    resp = _poll_until(
        ctx, probe,
        lambda r: sum(d["SampleCount"] for d in r.get("Datapoints", [])) == total,
        timeout_s=POLL_BUDGET_S,
        description=f"{int(total)} datapoints readable through GetMetricStatistics",
    )
    got = {
        d["Timestamp"].astimezone(timezone.utc): (d["Sum"], d["SampleCount"])
        for d in resp["Datapoints"]
    }
    assert got == expected, (
        f"per-minute (Sum, SampleCount): expected {sorted(expected.items())}, got {sorted(got.items())}"
    )
    for d in resp["Datapoints"]:
        assert d.get("Unit") == "Count", f"expected Unit 'Count' on every datapoint, got {d!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
