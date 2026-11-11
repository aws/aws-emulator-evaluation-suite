"""get-metric-data-stats-and-average-expression-match-put-values."""
from __future__ import annotations

import math
import random
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "get-metric-data-stats-and-average-expression-match-put-values"
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
    """GetMetricData aggregates random PutMetricData values server-side: Sum, SampleCount, Minimum
    and Maximum queries return the values' own totals, and a metric-math expression dividing Sum by
    SampleCount returns their mean."""
    rng = random.SystemRandom()
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-cwgmd-ns-")
    metric_name = "BytesProcessed"
    minute = (datetime.now(timezone.utc) - timedelta(minutes=5)).replace(second=0, microsecond=0)
    values = rng.sample(range(10, 9000), rng.randint(3, 7))
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {"MetricName": metric_name, "Timestamp": minute + timedelta(seconds=i), "Value": float(v),
             "Unit": "Bytes"}
            for i, v in enumerate(values)
        ],
    )

    def stat(qid, name):
        return {
            "Id": qid,
            "MetricStat": {
                "Metric": {"Namespace": namespace, "MetricName": metric_name},
                "Period": 60,
                "Stat": name,
                "Unit": "Bytes",
            },
        }

    queries = [
        stat("total", "Sum"),
        stat("count", "SampleCount"),
        stat("low", "Minimum"),
        stat("high", "Maximum"),
        {"Id": "mean", "Expression": "total / count"},
    ]
    expected = {
        "total": float(sum(values)),
        "count": float(len(values)),
        "low": float(min(values)),
        "high": float(max(values)),
        "mean": sum(values) / len(values),
    }

    def probe():
        return cw.get_metric_data(
            MetricDataQueries=queries,
            StartTime=minute,
            EndTime=minute + timedelta(minutes=1),
        )

    def by_id(resp):
        return {r["Id"]: r for r in resp.get("MetricDataResults", [])}

    # Every datum is ingested once the SampleCount query reports all of them.
    resp = _poll_until(
        ctx, probe,
        lambda r: by_id(r).get("count", {}).get("Values") == [float(len(values))],
        timeout_s=POLL_BUDGET_S,
        description=f"SampleCount {len(values)} readable through GetMetricData",
    )
    results = by_id(resp)
    assert sorted(results) == sorted(expected), f"result ids: expected {sorted(expected)}, got {sorted(results)}"
    for qid, want in expected.items():
        r = results[qid]
        assert r.get("StatusCode") == "Complete", f"query {qid}: expected StatusCode Complete, got {r!r}"
        assert len(r["Values"]) == 1 and math.isclose(r["Values"][0], want, rel_tol=1e-9), (
            f"query {qid}: expected one value {want}, got {r['Values']!r}"
        )
        assert [t.astimezone(timezone.utc) for t in r["Timestamps"]] == [minute], (
            f"query {qid}: expected one timestamp {minute.isoformat()}, got {r['Timestamps']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
