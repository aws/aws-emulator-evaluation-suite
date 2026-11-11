"""logs-insights-semantics-no-matching-data-completes-with-empty-results."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "logs-insights-semantics-no-matching-data-completes-with-empty-results"
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


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """After a matching predicate returns every planted row, a non-matching one completes with no
    results and recordsMatched 0, as do a group with no events and `stats count(*)` over no data.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-lisem-empty-")
    empty = ctx.unique_name("sim2real-lisem-empty-bare-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: svc.delete_log_group(logGroupName=group))
    svc.create_log_group(logGroupName=empty)
    ctx.on_cleanup(lambda: svc.delete_log_group(logGroupName=empty))

    base = int(time.time() * 1000) - 300_000
    levels = ["INFO", "WARN", "INFO", "ERROR"]
    _put(svc, group, "s", [{"timestamp": base + i * 1000, "message": json.dumps({"level": lv, "i": i})}
                           for i, lv in enumerate(levels)])
    start_s, end_s = base // 1000 - 60, int(time.time()) + 60

    # Positive control: the data is there and a matching predicate returns every row.
    ctl = _query_until(svc, [group], start_s, end_s,
                       "filter ispresent(level) | fields i | sort i asc",
                       lambda r: len(r["results"]) == len(levels), what="control rows visible")
    assert _rows(ctl) == [{"i": str(i)} for i in range(len(levels))], f"control rows {_rows(ctl)!r}"

    for label, groups, q in (
        ("non-matching filter", [group], "filter level = 'FATAL' | fields i"),
        ("non-matching regex", [group], "filter @message like /level\":\\s*\"TRACE/ | fields @message"),
        ("stats over no matches", [group], "filter level = 'FATAL' | stats count(*) as n"),
        ("never-written group", [empty], "fields @timestamp, @message"),
        ("stats over never-written group", [empty], "stats count(*) as n"),
    ):
        resp = _run_query(svc, groups, start_s, end_s, q)
        assert resp["status"] == "Complete", f"{label}: an empty answer is still Complete, got {resp['status']!r}"
        assert resp["results"] == [], f"{label}: expected an EMPTY results list, got {resp['results']!r}"
        assert resp["statistics"]["recordsMatched"] == 0.0, f"{label}: recordsMatched {resp['statistics']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
