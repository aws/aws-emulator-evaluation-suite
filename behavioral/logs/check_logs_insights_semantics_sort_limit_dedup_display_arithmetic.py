"""logs-insights-semantics-sort-limit-dedup-display-arithmetic."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "logs-insights-semantics-sort-limit-dedup-display-arithmetic"
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


_JSON = [  # id, svc, ms, user -- ms chosen so numeric and lexicographic order disagree
    ("e01", "api", 120, "alice"),
    ("e02", "api", 30, "bob"),
    ("e03", "db", 450, "alice"),
    ("e04", "db", 80, "carol"),
    ("e05", "db", 900, "bob"),
    ("e06", "web", 5, "alice"),
]


def _num(text):
    f = float(text)
    return str(int(f)) if f == int(f) else text


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """`sort` orders numbers numerically, `limit` truncates after sorting, `dedup` keeps the first row
    per key in both sort directions, `display` restricts columns, and field arithmetic is exact.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-lisem-sort-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: svc.delete_log_group(logGroupName=group))

    base = int(time.time() * 1000) - 300_000
    js = [dict(id=i, svc=s, ms=ms, user=u) for i, s, ms, u in _JSON]
    _put(svc, group, "s", [{"timestamp": base + n * 1000, "message": json.dumps(d)}
                           for n, d in enumerate(js)])
    start_s, end_s = base // 1000 - 60, int(time.time()) + 60
    _query_until(svc, [group], start_s, end_s, "stats count(*) as n",
                 lambda r: _rows(r) == [{"n": str(len(js))}], what="all events visible")

    def q(text):
        resp = _run_query(svc, [group], start_s, end_s, text)
        assert resp["status"] == "Complete", f"{text!r} ended {resp['status']!r}"
        return _rows(resp)

    by_desc = sorted(js, key=lambda d: -d["ms"])
    by_asc = sorted(js, key=lambda d: d["ms"])

    got = q("fields id, ms | sort ms desc | limit 3")
    want = [{"id": d["id"], "ms": str(d["ms"])} for d in by_desc[:3]]
    assert got == want, f"sort ms desc | limit 3 gave {got!r}, expected {want!r}"

    got = q("fields id, ms | sort ms asc | limit 2")
    want = [{"id": d["id"], "ms": str(d["ms"])} for d in by_asc[:2]]
    assert got == want, f"sort ms asc | limit 2 gave {got!r}, expected {want!r}"

    for direction, ordered in (("desc", by_desc), ("asc", by_asc)):
        seen, want = set(), []
        for d in ordered:
            if d["svc"] not in seen:
                seen.add(d["svc"])
                want.append({"id": d["id"], "svc": d["svc"], "ms": str(d["ms"])})
        got = q(f"fields id, svc, ms | sort ms {direction} | dedup svc")
        assert got == want, f"sort ms {direction} | dedup svc gave {got!r}, expected {want!r}"

    got = q("fields id, svc, ms, user | sort id asc | display id, user")
    want = [{"id": d["id"], "user": d["user"]} for d in sorted(js, key=lambda d: d["id"])]
    assert got == want, f"display id, user must emit only those columns, got {got!r}"

    got = q("fields id, ms * 2 + 1 as x, ms / 4 as y, ms % 7 as z | sort id asc")
    want = []
    for d in sorted(js, key=lambda d: d["id"]):
        y = d["ms"] / 4
        want.append({"id": d["id"], "x": str(d["ms"] * 2 + 1),
                     "y": str(int(y)) if y == int(y) else str(y), "z": str(d["ms"] % 7)})
    got = [{k: (_num(v) if k != "id" else v) for k, v in r.items()} for r in got]
    assert got == want, f"field arithmetic gave {got!r}, hand computation {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
