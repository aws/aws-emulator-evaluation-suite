"""logs-insights-semantics-filter-operators-select-exact-sets."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "logs-insights-semantics-filter-operators-select-exact-sets"
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


_JSON = [  # id, level, svc, ms, user
    ("e01", "ERROR", "api", 120, "alice"),
    ("e02", "INFO", "api", 30, "bob"),
    ("e03", "WARN", "db", 450, "alice"),
    ("e04", "INFO", "db", 80, "carol"),
    ("e05", "ERROR", "db", 900, "bob"),
    ("e06", "DEBUG", "web", 5, "alice"),
]
_TEXT = [
    "GET /orders/17 status=200 user=alice took=35ms",
    "POST /orders status=201 user=bob took=120ms",
    "GET /health status=500 user=carol took=7ms",
]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Each `filter` operator selects exactly the ids or messages a hand evaluation of the predicate
    selects over the JSON events and text lines the check wrote.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-lisem-filter-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: svc.delete_log_group(logGroupName=group))

    base = int(time.time() * 1000) - 300_000
    js = [dict(id=i, level=lv, svc=s, ms=ms, user=u) for i, lv, s, ms, u in _JSON]
    _put(svc, group, "json", [{"timestamp": base + n * 1000, "message": json.dumps(d)}
                              for n, d in enumerate(js)])
    _put(svc, group, "text", [{"timestamp": base + 10_000 + n * 1000, "message": m}
                              for n, m in enumerate(_TEXT)])
    start_s, end_s = base // 1000 - 60, int(time.time()) + 60
    total = len(js) + len(_TEXT)
    _query_until(svc, [group], start_s, end_s, "stats count(*) as n",
                 lambda r: _rows(r) == [{"n": str(total)}], what=f"all {total} events visible")

    def ids(query):
        resp = _run_query(svc, [group], start_s, end_s, query + " | fields id | sort id asc")
        assert resp["status"] == "Complete", f"{query!r} ended {resp['status']!r}"
        return [r.get("id") for r in _rows(resp)]

    cases = {
        "filter level = 'ERROR'": [d["id"] for d in js if d["level"] == "ERROR"],
        "filter level != 'INFO' and ispresent(level)": [d["id"] for d in js if d["level"] != "INFO"],
        "filter ms > 100 and ms <= 450": [d["id"] for d in js if 100 < d["ms"] <= 450],
        "filter @message not like 'alice' and ispresent(id)": [
            d["id"] for d in js if "alice" not in json.dumps(d)],
        "filter level in ['WARN', 'DEBUG']": [d["id"] for d in js if d["level"] in ("WARN", "DEBUG")],
        "filter user =~ /^(b|c)/": [d["id"] for d in js if d["user"][0] in "bc"],
    }
    for query, want in cases.items():
        got = ids(query)
        assert got == sorted(want), f"{query!r} selected {got!r}, hand evaluation selects {sorted(want)!r}"

    def messages(query):
        resp = _run_query(svc, [group], start_s, end_s, query + " | fields @message | sort @message asc")
        assert resp["status"] == "Complete", f"{query!r} ended {resp['status']!r}"
        return [r["@message"] for r in _rows(resp)]

    text_cases = {
        # substring over @message: matches only the two lines containing "orders"
        "filter @message like 'orders'": [m for m in _TEXT if "orders" in m],
        # regex over @message: a 5xx status only
        "filter @message like /status=5\\d\\d/": [m for m in _TEXT if "status=5" in m],
        # substring test is case-sensitive: 'get' is not in any line
        "filter @message like 'get'": [],
    }
    for query, want in text_cases.items():
        got = messages(query)
        assert got == sorted(want), f"{query!r} selected {got!r}, hand evaluation selects {sorted(want)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
