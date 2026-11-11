"""logs-insights-semantics-multi-group-rows-attributed-via-log."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "logs-insights-semantics-multi-group-rows-attributed-via-log"
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
    """One query over two groups scans 2 groups and returns every row with @log naming the group it was
    written to, in timestamp order; a group left out of logGroupNames contributes no rows.
    """
    svc = ctx.client("logs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    ga = ctx.unique_name("sim2real-lisem-multi-a-")
    gb = ctx.unique_name("sim2real-lisem-multi-b-")
    gc = ctx.unique_name("sim2real-lisem-multi-c-")
    for g in (ga, gb, gc):
        svc.create_log_group(logGroupName=g)
        ctx.on_cleanup(lambda g=g: svc.delete_log_group(logGroupName=g))

    base = int(time.time() * 1000) - 300_000
    plan = {ga: [0, 3, 6], gb: [1, 2, 4, 5, 7], gc: [8]}
    for g, offsets in plan.items():
        _put(svc, g, "s", [{"timestamp": base + o * 1000, "message": f"src={g} seq={o}"} for o in offsets])
    start_s, end_s = base // 1000 - 60, int(time.time()) + 60
    counts = {f"{account}:{g}": str(len(plan[g])) for g in (ga, gb)}

    resp = _query_until(svc, [ga, gb], start_s, end_s, "stats count(*) as n by @log",
                        lambda r: {x["@log"]: x["n"] for x in _rows(r)} == counts,
                        what="per-group counts over A+B")
    assert resp["statistics"]["logGroupsScanned"] == 2.0, f"logGroupsScanned {resp['statistics']!r} != 2"

    rows = _rows(_run_query(svc, [ga, gb], start_s, end_s,
                            "fields @log, @message | sort @timestamp asc"))
    want = sorted(((o, g) for g in (ga, gb) for o in plan[g]))
    expected = [{"@log": f"{account}:{g}", "@message": f"src={g} seq={o}"} for o, g in want]
    assert rows == expected, f"merged rows/attribution differ:\n got={rows!r}\nwant={expected!r}"

    # Group C was written but not named: none of its rows may appear.
    leaked = [r for r in rows if gc in r["@message"] or r["@log"].endswith(":" + gc)]
    assert not leaked, f"rows from a group outside logGroupNames leaked in: {leaked!r}"
    only_c = _query_until(svc, [gc], start_s, end_s, "fields @log, @message",
                          lambda r: len(r["results"]) == 1, what="group C holds its event")
    assert _rows(only_c) == [{"@log": f"{account}:{gc}", "@message": f"src={gc} seq=8"}], _rows(only_c)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
