"""get-metric-data-returns-only-returndata-queries-keyed-by-id."""
from __future__ import annotations

import math
import random
import string
import time
from datetime import UTC, datetime, timedelta

from behavioral_harness import tags

CHECK = "get-metric-data-returns-only-returndata-queries-keyed-by-id"
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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricData returns exactly the queries with ReturnData left on, each under its own Id with
    its own value, and none of the hidden metric queries; each expression is computed from hidden
    inputs listed before or after it."""
    rng = random.SystemRandom()
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-cwhide-ns-")
    minute = (datetime.now(UTC) - timedelta(minutes=5)).replace(second=0, microsecond=0)
    suffix = "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(6))
    a, b, c, d = (float(v) for v in rng.sample(range(1, 5000), 4))
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {"MetricName": name, "Timestamp": minute, "Value": v, "Unit": "Count"}
            for name, v in (("Alpha", a), ("Beta", b), ("Gamma", c), ("Delta", d))
        ],
    )

    def stat(qid, name, *, visible):
        return {
            "Id": qid,
            "MetricStat": {
                "Metric": {"Namespace": namespace, "MetricName": name},
                "Period": 60,
                "Stat": "Maximum",
            },
            "ReturnData": visible,
        }

    ida, idb, idc, idd = f"a{suffix}", f"b{suffix}", f"c{suffix}", f"d{suffix}"
    ids, idr, idf = f"sum{suffix}", f"ratio{suffix}", f"diff{suffix}"
    queries = [
        {"Id": ids, "Expression": f"{ida} + {idb}"},
        stat(idd, "Delta", visible=True),
        stat(ida, "Alpha", visible=False),
        {"Id": idr, "Expression": f"{idc} / {ida}"},
        stat(idc, "Gamma", visible=True),
        stat(idb, "Beta", visible=False),
        {"Id": idf, "Expression": f"{idc} - {idb}"},
    ]
    expected = {ids: a + b, idr: c / a, idd: d, idc: c, idf: c - b}
    hidden = {ida, idb}
    window = {"StartTime": minute, "EndTime": minute + timedelta(minutes=1)}

    def probe():
        return cw.get_metric_data(MetricDataQueries=queries, **window)

    # Each metric holds one datum, so every returned series has its value once all four are ingested.
    response = _poll_until(
        ctx, probe,
        lambda r: len(r.get("MetricDataResults", [])) == len(expected)
        and all(len(x.get("Values", [])) == 1 for x in r["MetricDataResults"]),
        timeout_s=POLL_BUDGET_S,
        description="every returned query carries its one datapoint",
    )
    results = response["MetricDataResults"]
    got_ids = [r["Id"] for r in results]
    assert sorted(got_ids) == sorted(expected), (
        f"results: expected exactly the ReturnData queries {sorted(expected)}, got {got_ids}"
    )
    leaked = hidden & set(got_ids)
    assert not leaked, f"results include the ReturnData=false queries {sorted(leaked)}"
    for r in results:
        want = expected[r["Id"]]
        assert r.get("StatusCode") == "Complete", f"query {r['Id']}: expected StatusCode Complete, got {r!r}"
        assert math.isclose(r["Values"][0], want, rel_tol=1e-9), (
            f"query {r['Id']}: expected {want}, got {r['Values']!r}"
        )
        assert [t.astimezone(UTC) for t in r["Timestamps"]] == [minute], (
            f"query {r['Id']}: expected one timestamp {minute.isoformat()}, got {r['Timestamps']!r}"
        )

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
