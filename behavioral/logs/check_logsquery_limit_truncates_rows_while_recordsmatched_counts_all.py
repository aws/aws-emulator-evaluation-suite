"""logsquery-limit-truncates-rows-while-recordsmatched-counts-all."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "logsquery-limit-truncates-rows-while-recordsmatched-counts-all"
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
    """``limit 3`` returns 3 of the 8 seeded events while ``recordsMatched`` still counts all 8 and
    ``resultCount`` reports 3; the 8 are first seen by a wider query.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-lqlimit-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    marker = ctx.unique_name("mk")

    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)

    n_seeded = 8
    base_ms = _now_ms()
    messages = {f"REQ {marker} seq={i}" for i in range(n_seeded)}
    svc.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[
            {"timestamp": base_ms - (n_seeded - i) * 1000, "message": f"REQ {marker} seq={i}"}
            for i in range(n_seeded)
        ],
    )

    now_s = base_ms // 1000
    base_query = f"fields @message | filter @message like /{marker}/"

    # 1. Converge: with a limit above the match count, every seeded event is a row.
    full = _await_rows(svc, group, f"{base_query} | limit 20", now_s - 600, now_s + 120,
                       expect=n_seeded)
    assert {_row_map(r)["@message"] for r in full["results"]} == messages, (
        f"the unbounded query must return exactly the {n_seeded} seeded events, got "
        f"{sorted(_row_map(r)['@message'] for r in full['results'])!r}"
    )
    assert (full.get("statistics") or {}).get("recordsMatched") == float(n_seeded), (
        f"recordsMatched must be {n_seeded} for the unbounded query, got {full.get('statistics')!r}"
    )

    # 2. Break exactly one thing: bound the same query to 3 rows.
    capped = _run_query(svc, group, f"{base_query} | limit 3", now_s - 600, now_s + 120)
    rows = [_row_map(r) for r in capped["results"]]
    assert len(rows) == 3, f"'limit 3' must return exactly 3 rows, got {len(rows)}: {rows!r}"
    returned = {r["@message"] for r in rows}
    assert returned <= messages, (
        f"every returned row must be one of the seeded events, got {sorted(returned)!r}"
    )
    assert len(returned) == 3, f"the 3 returned rows must be distinct events, got {rows!r}"

    stats = capped.get("statistics") or {}
    assert stats.get("recordsMatched") == float(n_seeded), (
        f"'limit 3' must not change recordsMatched: the filter still matched all {n_seeded} "
        f"events, got {stats!r}"
    )
    assert stats.get("resultCount") == 3.0, (
        f"resultCount must report the {len(rows)} rows actually returned, got {stats!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
