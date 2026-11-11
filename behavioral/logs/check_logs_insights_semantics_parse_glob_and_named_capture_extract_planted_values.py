"""logs-insights-semantics-parse-glob-and-named-capture-extract-planted-values."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags

CHECK = "logs-insights-semantics-parse-glob-and-named-capture-extract-planted-values"
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


# verb, path, status, user, took(ms) -- the values the parse patterns must recover.
_PLANTED = [
    ("GET", "/orders/17", "200", "alice", "35"),
    ("POST", "/orders", "201", "bob", "120"),
    ("GET", "/health", "500", "carol", "7"),
]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """`parse` with a glob and with a named-capture regex binds exactly the planted tokens, a line the
    pattern does not match yields no parsed fields, and `sum` over a parsed field equals the planted total.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-lisem-parse-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: svc.delete_log_group(logGroupName=group))

    base = int(time.time() * 1000) - 300_000
    lines = [f"{v} {p} status={s} user={u} took={t}ms" for v, p, s, u, t in _PLANTED]
    noise = "heartbeat ok"
    events = [{"timestamp": base + n * 1000, "message": m} for n, m in enumerate(lines)]
    events.append({"timestamp": base + 10_000, "message": noise})
    _put(svc, group, "access", events)
    start_s, end_s = base // 1000 - 60, int(time.time()) + 60
    _query_until(svc, [group], start_s, end_s, "stats count(*) as n",
                 lambda r: _rows(r) == [{"n": "4"}], what="all 4 events visible")

    # (1) glob: five wildcards, bound in order.
    glob_q = ("parse @message '* * status=* user=* took=*ms' as verb, path, code, who, took"
              " | filter @message like 'status=' | sort @timestamp asc"
              " | display verb, path, code, who, took")
    resp = _run_query(svc, [group], start_s, end_s, glob_q)
    assert resp["status"] == "Complete", f"glob parse ended {resp['status']!r}"
    want = [dict(zip(("verb", "path", "code", "who", "took"), p)) for p in _PLANTED]
    assert _rows(resp) == want, f"glob parse bound {_rows(resp)!r}, planted {want!r}"

    # (2) named-capture regex, expected values from Python's own evaluation of the same regex.
    rx = r"status=(?<code>\d+) user=(?<who>\w+) took=(?<took>\d+)ms"
    py = re.compile(rx.replace("(?<", "(?P<"))
    regex_q = (f"parse @message /{rx}/ | filter @message like 'status='"
               " | sort @timestamp asc | display code, who, took")
    resp = _run_query(svc, [group], start_s, end_s, regex_q)
    assert resp["status"] == "Complete", f"regex parse ended {resp['status']!r}"
    want = [py.search(m).groupdict() for m in lines]
    assert _rows(resp) == want, f"regex parse bound {_rows(resp)!r}, planted {want!r}"

    # (3) a line the pattern does not match gets no parsed fields at all.
    partial_q = ("parse @message 'GET * status=*' as path, code"
                 " | sort @timestamp asc | display @message, path, code")
    rows = _rows(_run_query(svc, [group], start_s, end_s, partial_q))
    want = []
    for m in lines + [noise]:
        mt = re.search(r"GET (.*?) status=(.*)", m)
        want.append({"@message": m, "path": mt.group(1), "code": mt.group(2)} if mt else {"@message": m})
    assert rows == want, f"partial glob bound {rows!r}; hand evaluation gives {want!r}"

    # (4) parsed values flow into aggregation.
    agg_q = f"parse @message /{rx}/ | stats sum(took) as total, count(who) as n"
    rows = _rows(_run_query(svc, [group], start_s, end_s, agg_q))
    total = sum(int(p[4]) for p in _PLANTED)
    assert rows == [{"total": str(total), "n": str(len(_PLANTED))}], (
        f"sum/count over parsed fields returned {rows!r}, expected total={total} n={len(_PLANTED)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
