"""logsquery-stats-group-key-absent-for-events-without-the-field."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "logsquery-stats-group-key-absent-for-events-without-the-field"
GROUP = 'insights-query'
SERVICES = ['logs']


def _now_ms() -> int:
    return int(time.time() * 1000)


def _row_map(row):
    return {f["field"]: f["value"] for f in row}


def _run_query(svc, group, query, start_s, end_s, *, timeout_s=60):
    """One start+poll cycle, polled to a terminal status. Never asserts how long it took."""
    qid = svc.start_query(
        logGroupNames=[group], startTime=start_s, endTime=end_s, queryString=query
    )["queryId"]
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = svc.get_query_results(queryId=qid)
        if last["status"] in ("Complete", "Failed", "Cancelled", "Timeout"):
            assert last["status"] == "Complete", (
                f"query {query!r} ended in status {last['status']!r}: {last!r}"
            )
            return last
        time.sleep(1.5)
    raise AssertionError(f"query {qid} never reached a terminal status in {timeout_s}s: {last!r}")


def _await_rows(svc, group, query, start_s, end_s, *, expect, timeout_s=150):
    """Retry the whole start+poll cycle until the ingested events are visible to the query
    engine. Ingestion into a brand-new log group is eventually consistent, so this polls for
    the value ARRIVING and never asserts how long ingestion took."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _run_query(svc, group, query, start_s, end_s)
        if len(last.get("results", [])) == expect:
            return last
        time.sleep(5.0)
    raise AssertionError(
        f"query {query!r} never returned {expect} rows within {timeout_s}s; last={last!r}"
    )


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """``stats count(*) by svc`` puts the event without ``svc`` into its own row that omits the key
    (alpha 3, beta 2, keyless 1), counting every event once; recordsMatched covers all six.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-lqnullkey-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    marker = ctx.unique_name("mk")

    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)

    parseable = [("alpha", 100), ("alpha", 200), ("alpha", 300), ("beta", 9), ("beta", 25)]
    base_ms = _now_ms()
    events = [
        {"timestamp": base_ms - (len(parseable) - i) * 1000,
         "message": f"REQ {marker} svc={s} lat={lat}"}
        for i, (s, lat) in enumerate(parseable)
    ]
    # One line of a different shape: the same filter selects it, the parse cannot match it, so it
    # has no `svc` to group by.
    events.append({"timestamp": base_ms - 500, "message": f"HEARTBEAT {marker} no fields here"})
    svc.put_log_events(logGroupName=group, logStreamName=stream, logEvents=events)

    now_s = base_ms // 1000
    query = (
        f"filter @message like /{marker}/"
        ' | parse @message "svc=* lat=*" as svc, lat'
        " | stats count(*) as n by svc"
        " | sort n desc"
    )
    res = _await_rows(svc, group, query, now_s - 600, now_s + 120, expect=3)

    rows = [_row_map(r) for r in res["results"]]
    assert rows[0] == {"svc": "alpha", "n": "3"}, (
        f"the largest group must be alpha with 3 events under 'sort n desc', got {rows[0]!r}"
    )
    assert rows[1] == {"svc": "beta", "n": "2"}, (
        f"the second group must be beta with 2 events, got {rows[1]!r}"
    )
    # The claim: the no-such-field group is present, counted once, and carries NO grouping key.
    assert rows[2] == {"n": "1"}, (
        "the events with no parsed 'svc' must form one aggregate row that omits the grouping key "
        f"entirely -- no empty string, no null, no placeholder; got {rows[2]!r}"
    )
    assert "svc" not in rows[2], (
        f"the no-such-field row must not carry an 'svc' field at all, got {sorted(rows[2])!r}"
    )

    total = sum(int(r["n"]) for r in rows)
    assert total == len(events), (
        f"every matched event must be counted in exactly one group: the groups sum to {total}, "
        f"but {len(events)} events were seeded ({rows!r})"
    )
    assert (res.get("statistics") or {}).get("recordsMatched") == float(len(events)), (
        f"recordsMatched must show all {len(events)} seeded events were scanned in this same "
        f"answer, got {res.get('statistics')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
