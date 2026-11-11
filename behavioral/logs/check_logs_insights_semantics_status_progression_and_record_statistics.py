"""logs-insights-semantics-status-progression-and-record-statistics."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "logs-insights-semantics-status-progression-and-record-statistics"
GROUP = 'insights'
SERVICES = ['logs']


_TERMINAL = ("Complete", "Failed", "Cancelled", "Timeout", "Unknown")


def _rows(resp, *, drop=("@ptr",)):
    return [{f["field"]: f["value"] for f in row if f["field"] not in drop} for row in resp["results"]]


def _put(svc, group, stream, events):
    svc.create_log_stream(logGroupName=group, logStreamName=stream)
    svc.put_log_events(
        logGroupName=group, logStreamName=stream,
        logEvents=sorted(events, key=lambda e: e["timestamp"]),
    )


def _run_tracking(svc, groups, start_s, end_s, query, *, timeout_s=120):
    """Start a query and poll tightly, recording every distinct status observed."""
    qid = svc.start_query(logGroupNames=groups, startTime=start_s, endTime=end_s,
                          queryString=query)["queryId"]
    seen = []
    deadline = time.monotonic() + timeout_s
    while True:
        resp = svc.get_query_results(queryId=qid)
        if not seen or seen[-1] != resp["status"]:
            seen.append(resp["status"])
        if resp["status"] in _TERMINAL:
            resp["queryId"] = qid
            return resp, seen
        if time.monotonic() > deadline:
            raise AssertionError(f"query {qid} never reached a terminal status; saw {seen!r}")
        time.sleep(0.25)


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query status only moves forward to Complete, and statistics count what was written:
    recordsMatched/recordsScanned equal all events or the matching ones, logGroupsScanned is 1, and
    resultCount equals the rows returned; DescribeQueries reports Complete for the same query.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-lisem-stat-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: svc.delete_log_group(logGroupName=group))

    n_total, match_every = 12, 3  # every 3rd event is a match -> 4 matches
    base = int(time.time() * 1000) - 300_000
    events = [{"timestamp": base + i * 1000,
               "message": json.dumps({"seq": i, "kind": "hit" if i % match_every == 0 else "miss"})}
              for i in range(n_total)]
    n_match = sum(1 for i in range(n_total) if i % match_every == 0)
    _put(svc, group, "s", events)
    start_s, end_s = base // 1000 - 60, int(time.time()) + 60

    # Poll until the unfiltered count sees every event (ingestion is eventually consistent).
    deadline = time.monotonic() + 180
    while True:
        full, seen = _run_tracking(svc, [group], start_s, end_s, "stats count(*) as n")
        if full["status"] == "Complete" and _rows(full) == [{"n": str(n_total)}]:
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"unfiltered count never reached {n_total}: {_rows(full)!r} {full.get('statistics')!r}")
        time.sleep(3)

    order = ["Scheduled", "Running", "Complete"]
    for label, s in (("unfiltered", seen),):
        assert s[-1] == "Complete", f"{label}: lifecycle must end Complete, saw {s!r}"
        assert all(x in order for x in s), f"{label}: unexpected status in {s!r}"
        assert [order.index(x) for x in s] == sorted(order.index(x) for x in s), (
            f"{label}: status regressed instead of advancing: {s!r}"
        )
    st = full["statistics"]
    assert st["recordsMatched"] == float(n_total), f"unfiltered recordsMatched {st!r} != {n_total}"
    assert st["recordsScanned"] == float(n_total), f"unfiltered recordsScanned {st!r} != {n_total}"
    assert st["logGroupsScanned"] == 1.0, f"logGroupsScanned {st!r} != 1"
    assert st["bytesScanned"] >= sum(len(e["message"]) for e in events), (
        f"bytesScanned {st['bytesScanned']!r} is less than the {sum(len(e['message']) for e in events)} "
        "message bytes written"
    )

    filt, seen = _run_tracking(svc, [group], start_s, end_s,
                               "filter kind = 'hit' | fields seq | sort seq asc")
    assert seen[-1] == "Complete", f"filtered lifecycle ended {seen!r}"
    assert [order.index(x) for x in seen] == sorted(order.index(x) for x in seen), (
        f"filtered: status regressed: {seen!r}"
    )
    rows = _rows(filt)
    assert rows == [{"seq": str(i)} for i in range(n_total) if i % match_every == 0], (
        f"filtered rows {rows!r} are not exactly the planted hits"
    )
    st = filt["statistics"]
    assert st["recordsMatched"] == float(n_match), f"filtered recordsMatched {st!r} != {n_match}"
    assert n_match <= st["recordsScanned"] <= n_total, (
        f"recordsScanned {st['recordsScanned']!r} outside [{n_match}, {n_total}]"
    )
    assert st["resultCount"] == float(len(rows)), f"resultCount {st!r} != {len(rows)} rows returned"

    described = {}
    for page in svc.get_paginator("describe_queries").paginate(logGroupName=group):
        for qd in page["queries"]:
            described[qd["queryId"]] = qd["status"]
    assert described.get(filt["queryId"]) == "Complete", (
        f"DescribeQueries must report the filtered query Complete, got {described.get(filt['queryId'])!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
