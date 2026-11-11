"""logsquery-time-window-excludes-events-outside-the-range."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "logsquery-time-window-excludes-events-outside-the-range"
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


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A wide ``[startTime, endTime]`` window returns all three seeded events; moving only startTime
    past the oldest returns the two newer ones and excludes it, with recordsMatched 3 then 2.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-lqwindow-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    marker = ctx.unique_name("mk")

    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)

    # Three events, far enough apart that no boundary-inclusivity question arises.
    base_ms = _now_ms()
    slots = [("old", 1800), ("mid", 900), ("new", 60)]
    svc.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[
            {"timestamp": base_ms - back * 1000, "message": f"WINDOW {marker} slot={slot}"}
            for slot, back in slots
        ],
    )

    now_s = base_ms // 1000
    query = f"fields @message | filter @message like /{marker}/ | sort @timestamp asc"

    def _slots(res):
        return [_row_map(r)["@message"].rsplit("slot=", 1)[1] for r in res["results"]]

    # 1. WIDE window [-2400s, +120s] -- every seeded event is inside it. Converge here, so the
    #    narrow query below cannot pass on an event that simply had not been ingested yet.
    wide = _await_rows(svc, group, query, now_s - 2400, now_s + 120, expect=3)
    assert _slots(wide) == ["old", "mid", "new"], (
        f"the wide window must return all three seeded events oldest-first, got {_slots(wide)!r}"
    )
    assert (wide.get("statistics") or {}).get("recordsMatched") == 3.0, (
        f"the wide window must match 3 events, got {wide.get('statistics')!r}"
    )

    # 2. Break exactly one thing: move startTime forward past the oldest event.
    narrow = _run_query(svc, group, query, now_s - 1200, now_s + 120)
    got = _slots(narrow)
    assert got == ["mid", "new"], (
        "moving startTime from -2400s to -1200s must exclude the event at -1800s and keep the "
        f"other two, got {got!r}"
    )
    assert (narrow.get("statistics") or {}).get("recordsMatched") == 2.0, (
        "recordsMatched must count only the in-window events, got "
        f"{narrow.get('statistics')!r}"
    )
    assert "old" not in got, (
        f"the out-of-window event must be absent from the narrowed result, got {got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
