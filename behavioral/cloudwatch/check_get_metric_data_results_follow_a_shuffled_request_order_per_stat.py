"""get-metric-data-results-follow-a-shuffled-request-order-per-stat."""
from __future__ import annotations

import math
import random
import string
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "get-metric-data-results-follow-a-shuffled-request-order-per-stat"
GROUP = "ordering"
SERVICES = ["cloudwatch"]
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


def _poll_until(ctx, probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
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


_STATS = {
    "Sum": sum,
    "Minimum": min,
    "Maximum": max,
    "SampleCount": len,
    "Average": lambda vs: sum(vs) / len(vs),
}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricData returns one result per query in the order the request listed them, for a
    random permutation of random query Ids, each carrying its own statistic over its own metric."""
    rng = random.SystemRandom()
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-cwshuf-ns-")
    minute = (datetime.now(timezone.utc) - timedelta(minutes=5)).replace(second=0, microsecond=0)

    plan = []
    for stat_name in _STATS:
        qid = "q" + "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(8))
        metric = f"M{qid}"
        values = [float(v) for v in rng.sample(range(1, 1000), 3)]
        plan.append((qid, metric, stat_name, values))
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {"MetricName": metric, "Timestamp": minute + timedelta(seconds=i), "Value": v, "Unit": "Count"}
            for _, metric, _, values in plan
            for i, v in enumerate(values)
        ],
    )
    rng.shuffle(plan)
    queries = [
        {
            "Id": qid,
            "MetricStat": {
                "Metric": {"Namespace": namespace, "MetricName": metric},
                "Period": 60,
                "Stat": stat_name,
            },
        }
        for qid, metric, stat_name, _ in plan
    ]
    expected_order = [qid for qid, _, _, _ in plan]
    expected_values = {qid: float(_STATS[s](vs)) for qid, _, s, vs in plan}
    window = {"StartTime": minute, "EndTime": minute + timedelta(minutes=1)}

    def all_ingested():
        """True once every metric reports all three of its datapoints (a SampleCount per metric)."""
        resp = cw.get_metric_data(
            MetricDataQueries=[
                {"Id": f"n{qid}", "MetricStat": {
                    "Metric": {"Namespace": namespace, "MetricName": metric},
                    "Period": 60, "Stat": "SampleCount"}}
                for qid, metric, _, _ in plan
            ],
            **window,
        )
        return [r.get("Values") for r in resp.get("MetricDataResults", [])] == [[3.0]] * len(plan)

    _poll_until(ctx, all_ingested, bool, timeout_s=POLL_BUDGET_S,
                description="all three datapoints of every metric readable through GetMetricData")
    response = cw.get_metric_data(MetricDataQueries=queries, **window)
    results = response["MetricDataResults"]
    actual_order = [r["Id"] for r in results]
    assert actual_order == expected_order, (
        f"result order {actual_order} does not match request order {expected_order}"
    )
    for r in results:
        want = expected_values[r["Id"]]
        assert len(r["Values"]) == 1 and math.isclose(r["Values"][0], want, rel_tol=1e-9), (
            f"query {r['Id']}: expected one value {want}, got {r['Values']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
