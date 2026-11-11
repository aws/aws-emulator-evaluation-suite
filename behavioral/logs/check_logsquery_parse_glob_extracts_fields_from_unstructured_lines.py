"""logsquery-parse-glob-extracts-fields-from-unstructured-lines."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "logsquery-parse-glob-extracts-fields-from-unstructured-lines"
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
    """A ``parse`` glob extracts svc/lat/st from five unstructured lines, and the matching but
    unparseable HEARTBEAT line comes back as a row with ``@ptr`` only, with no parsed keys.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-lqparseglob-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    marker = ctx.unique_name("mk")

    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)

    # Five unstructured request lines of a fixed shape, plus one line of a DIFFERENT shape that
    # the same filter selects but the parse pattern cannot match.
    seeded = [
        ("alpha", "100", "200"),
        ("alpha", "200", "200"),
        ("alpha", "300", "500"),
        ("beta", "9", "200"),
        ("beta", "25", "404"),
    ]
    base_ms = _now_ms()
    events = [
        {"timestamp": base_ms - (len(seeded) - i) * 1000,
         "message": f"REQ {marker} svc={s} lat={lat} status={st}"}
        for i, (s, lat, st) in enumerate(seeded)
    ]
    events.append({"timestamp": base_ms, "message": f"HEARTBEAT {marker} no fields here"})
    svc.put_log_events(logGroupName=group, logStreamName=stream, logEvents=events)

    now_s = base_ms // 1000
    query = (
        f"filter @message like /{marker}/"
        ' | parse @message "svc=* lat=* status=*" as svc, lat, st'
        " | sort @timestamp asc"
    )
    res = _await_rows(svc, group, query, now_s - 600, now_s + 120, expect=6)

    stats = res.get("statistics") or {}
    assert stats.get("recordsMatched") == 6.0, (
        f"the filter must match all 6 seeded lines, got recordsMatched={stats.get('recordsMatched')!r}"
    )

    rows = [_row_map(r) for r in res["results"]]
    for i, (want_svc, want_lat, want_st) in enumerate(seeded):
        got = rows[i]
        assert (got.get("svc"), got.get("lat"), got.get("st")) == (want_svc, want_lat, want_st), (
            f"row {i}: parse must extract svc/lat/st = {(want_svc, want_lat, want_st)!r} from the "
            f"unstructured line, got {(got.get('svc'), got.get('lat'), got.get('st'))!r}"
        )
        assert got.get("@ptr"), f"row {i} must carry a @ptr pointer, got {got!r}"

    # Effect-absent: the line the parse pattern does not match is still a row, and carries NONE of
    # the parsed fields -- not empty strings, not nulls, the keys are simply absent. All that is
    # left of it is the pointer the engine adds itself.
    heartbeat = rows[5]
    assert set(heartbeat) == {"@ptr"}, (
        "an unmatched line must carry no parsed fields at all -- not empty strings, not nulls; "
        f"got fields {sorted(heartbeat)!r}"
    )
    assert sum(1 for r in rows if set(r) == {"@ptr"}) == 1, (
        "exactly one seeded line is unparseable, so exactly one row may be field-free; got "
        f"{[sorted(r) for r in rows]!r}"
    )

    # The rows above carry no @message, so name the last line separately: a projection query over
    # the same events, sorted the same way, must show the HEARTBEAT line last. That is what makes
    # the field-free row above attributable to THAT line rather than to an arbitrary one.
    named = _run_query(
        svc, group,
        f"filter @message like /{marker}/ | sort @timestamp asc | fields @message",
        now_s - 600, now_s + 120,
    )
    messages = [_row_map(r).get("@message") for r in named["results"]]
    assert len(messages) == 6, f"the projection query must see the same 6 lines, got {messages!r}"
    assert messages[5] == f"HEARTBEAT {marker} no fields here", (
        f"the newest line under 'sort @timestamp asc' must be the HEARTBEAT one, got {messages!r}"
    )
    assert all("svc=" in m for m in messages[:5]), (
        f"the other five lines must be the request-shaped ones, got {messages!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
