"""logs-insights-semantics-stats-aggregates-by-field-match-hand-computation."""
from __future__ import annotations

import json
import math
import time

from behavioral_harness import tags

CHECK = "logs-insights-semantics-stats-aggregates-by-field-match-hand-computation"
GROUP = 'insights'
SERVICES = ['logs']


_TERMINAL = ("Complete", "Failed", "Cancelled", "Timeout", "Unknown")


def _run_query(svc, groups, start_s, end_s, query, *, timeout_s=120, interval_s=1.0):
    qid = svc.start_query(
        logGroupNames=groups, startTime=start_s, endTime=end_s, queryString=query
    )["queryId"]
    deadline = time.monotonic() + timeout_s
    while True:
        resp = svc.get_query_results(queryId=qid)
        if resp["status"] in _TERMINAL:
            resp["queryId"] = qid
            return resp
        if time.monotonic() > deadline:
            raise AssertionError(f"query {qid} ({query!r}) still {resp['status']!r} after {timeout_s}s")
        time.sleep(interval_s)


def _rows(resp, *, drop=("@ptr",)):
    return [{f["field"]: f["value"] for f in row if f["field"] not in drop} for row in resp["results"]]


def _query_until(svc, groups, start_s, end_s, query, predicate, *, what, budget_s=180):
    """Ingestion is eventually consistent: re-run the query until its rows satisfy
    ``predicate`` or the budget is spent. Asserts content, never latency."""
    deadline = time.monotonic() + budget_s
    last = None
    while True:
        resp = _run_query(svc, groups, start_s, end_s, query)
        if resp["status"] == "Complete" and predicate(resp):
            return resp
        last = (resp["status"], _rows(resp, drop=()), resp.get("statistics"))
        if time.monotonic() > deadline:
            raise AssertionError(f"{what}: {query!r} never satisfied the expectation in {budget_s}s; last={last!r}")
        time.sleep(3)


def _put(svc, group, stream, events):
    svc.create_log_stream(logGroupName=group, logStreamName=stream)
    svc.put_log_events(
        logGroupName=group, logStreamName=stream,
        logEvents=sorted(events, key=lambda e: e["timestamp"]),
    )


_JSON = [  # svc, ms, user
    ("api", 120, "alice"),
    ("api", 30, "bob"),
    ("db", 450, "alice"),
    ("db", 80, "carol"),
    ("db", 900, "bob"),
    ("web", 5, "alice"),
]


def _nearest_rank(values, p):
    """Nearest-rank percentile: the ceil(p/100 * N)-th smallest value (1-based, min 1)."""
    s = sorted(values)
    return s[max(1, math.ceil(p / 100 * len(s))) - 1]


def _close(text, want):
    return abs(float(text) - want) < 1e-3


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """`stats` count/sum/avg/min/max/count_distinct/pct by a field equal a hand computation, `pct` is
    the nearest-rank percentile, and events without the `by` field form one keyless bucket.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-lisem-stats-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: svc.delete_log_group(logGroupName=group))

    base = int(time.time() * 1000) - 300_000
    events = [{"timestamp": base + n * 1000, "message": json.dumps({"svc": s, "ms": ms, "user": u})}
              for n, (s, ms, u) in enumerate(_JSON)]
    # Two events with no svc/ms/user: they must land in one keyless bucket.
    events += [{"timestamp": base + 20_000 + n * 1000, "message": f"no fields here {n}"} for n in range(2)]
    _put(svc, group, "s", events)
    start_s, end_s = base // 1000 - 60, int(time.time()) + 60
    _query_until(svc, [group], start_s, end_s, "stats count(*) as n",
                 lambda r: _rows(r) == [{"n": str(len(events))}], what="all events visible")

    q = ("stats count(*) as n, sum(ms) as s, avg(ms) as a, min(ms) as mn, max(ms) as mx,"
         " count_distinct(user) as u, pct(ms, 50) as p50 by svc | sort svc asc")
    resp = _run_query(svc, [group], start_s, end_s, q)
    assert resp["status"] == "Complete", f"stats query ended {resp['status']!r}"
    rows = _rows(resp)
    keyed = {r["svc"]: r for r in rows if "svc" in r}
    keyless = [r for r in rows if "svc" not in r]

    buckets = {}
    for s, ms, u in _JSON:
        buckets.setdefault(s, []).append((ms, u))
    assert sorted(keyed) == sorted(buckets), f"stats by svc produced buckets {sorted(keyed)!r}, wrote {sorted(buckets)!r}"
    for s, vals in buckets.items():
        ms = [v[0] for v in vals]
        r = keyed[s]
        assert r["n"] == str(len(ms)), f"{s}: count {r['n']!r} != {len(ms)}"
        assert _close(r["s"], sum(ms)), f"{s}: sum {r['s']!r} != {sum(ms)}"
        assert _close(r["a"], round(sum(ms) / len(ms), 4)), f"{s}: avg {r['a']!r} != {sum(ms) / len(ms)}"
        assert _close(r["mn"], min(ms)), f"{s}: min {r['mn']!r} != {min(ms)}"
        assert _close(r["mx"], max(ms)), f"{s}: max {r['mx']!r} != {max(ms)}"
        assert r["u"] == str(len({v[1] for v in vals})), f"{s}: count_distinct {r['u']!r}"
        assert _close(r["p50"], _nearest_rank(ms, 50)), (
            f"{s}: pct(ms,50) {r['p50']!r} != nearest-rank {_nearest_rank(ms, 50)} over {sorted(ms)}"
        )
    assert len(keyless) == 1 and keyless[0]["n"] == "2", (
        f"the 2 events lacking svc must form exactly one keyless bucket counting 2, got {keyless!r}"
    )

    # Grand-total percentiles across all six values, nearest-rank.
    all_ms = [ms for _, ms, _ in _JSON]
    pq = "filter ispresent(ms) | stats pct(ms, 10) as p10, pct(ms, 50) as p50, pct(ms, 90) as p90"
    rows = _rows(_run_query(svc, [group], start_s, end_s, pq))
    assert len(rows) == 1, f"a stats with no `by` returns exactly one row, got {rows!r}"
    for p in (10, 50, 90):
        got = rows[0][f"p{p}"]
        assert _close(got, _nearest_rank(all_ms, p)), (
            f"pct(ms,{p}) = {got!r}, nearest-rank over {sorted(all_ms)} is {_nearest_rank(all_ms, p)}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
