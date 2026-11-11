"""logsquery-display-projects-only-the-named-fields."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "logsquery-display-projects-only-the-named-fields"
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
    """``display`` restricts each row to the named parsed fields plus ``@ptr``, dropping the unnamed
    ``st``, while the same pipeline without ``display`` returns rows that carry ``st``.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-lqdisplay-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    marker = ctx.unique_name("mk")

    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)

    seeded = [("alpha", "100"), ("alpha", "200"), ("alpha", "300"), ("beta", "9"), ("beta", "25")]
    base_ms = _now_ms()
    svc.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[
            {"timestamp": base_ms - (len(seeded) - i) * 1000,
             "message": f"REQ {marker} svc={s} lat={lat} status=200"}
            for i, (s, lat) in enumerate(seeded)
        ],
    )

    now_s = base_ms // 1000
    pipeline = (
        f"filter @message like /{marker}/"
        ' | parse @message "svc=* lat=* status=*" as svc, lat, st'
        " | sort @timestamp asc"
    )

    # 1. The projected query: rows carry the two named fields and the engine's own @ptr, and
    #    nothing else -- `st` was parsed but not named, so it is gone.
    projected = _await_rows(svc, group, f"{pipeline} | display svc, lat", now_s - 600,
                            now_s + 120, expect=len(seeded))
    rows = [_row_map(r) for r in projected["results"]]
    for i, row in enumerate(rows):
        assert set(row) == {"svc", "lat", "@ptr"}, (
            "'display svc, lat' must restrict the row to those two fields plus the engine's "
            f"implicit @ptr; row {i} carried {sorted(row)!r}"
        )
    assert [(r["svc"], r["lat"]) for r in rows] == seeded, (
        f"the projected values must be the seeded ones in @timestamp order {seeded!r}, got "
        f"{[(r['svc'], r['lat']) for r in rows]!r}"
    )

    # 2. Control: the same pipeline without the display command still carries `st`, so its absence
    #    above is caused by `display` and not by the log group or by `parse`.
    unprojected = _run_query(svc, group, pipeline, now_s - 600, now_s + 120)
    control = [_row_map(r) for r in unprojected["results"]]
    assert len(control) == len(seeded), (
        f"the control query must still return all {len(seeded)} rows, got {len(control)}"
    )
    for i, row in enumerate(control):
        assert set(row) == {"svc", "lat", "st", "@ptr"}, (
            f"without 'display', row {i} must carry all three parsed fields and @ptr -- and no "
            f"@message, since the pipeline never projects one; got {sorted(row)!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
