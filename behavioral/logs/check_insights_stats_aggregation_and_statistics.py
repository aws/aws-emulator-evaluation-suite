"""insights-stats-aggregation-and-statistics."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "insights-stats-aggregation-and-statistics"
GROUP = 'insights'
SERVICES = ['logs']


# ===== helpers =====
def _now_ms() -> int:
    return int(time.time() * 1000)


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _row_map(row):
    return {f["field"]: f["value"] for f in row}


# ===== end helpers =====


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Logs Insights ``stats ... by`` query returns aggregate rows named by the query text over
    discovered JSON fields, and GetQueryResults reports a populated ``statistics`` block; the
    start+poll cycle is retried until rows appear because ingestion is eventually consistent.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-insightsstats-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)

    # 3x ERROR, 2x INFO -> a 2-row aggregate with known counts.
    levels = ["ERROR", "ERROR", "ERROR", "INFO", "INFO"]
    base = _now_ms()
    svc.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[
            {
                "timestamp": base - (len(levels) - i) * 1000,
                "message": json.dumps({"level": lvl, "seq": i}),
            }
            for i, lvl in enumerate(levels)
        ],
    )

    now_sec = base // 1000
    start_sec = now_sec - 300
    end_sec = now_sec + 300

    def _run_query(query_string, *, overall_timeout_s=180):
        """Start the query, poll to a terminal status, retry the whole cycle
        until the (eventually consistent) ingested events are visible to it."""
        deadline = time.monotonic() + overall_timeout_s
        last = None
        while time.monotonic() < deadline:
            query_id = svc.start_query(
                logGroupNames=[group],
                startTime=start_sec,
                endTime=end_sec,
                queryString=query_string,
            )["queryId"]
            last = _poll_until(
                lambda qid=query_id: svc.get_query_results(queryId=qid),
                lambda r: r.get("status") in ("Complete", "Failed", "Cancelled", "Timeout"),
                timeout_s=60,
                interval_s=2.0,
                description=f"query {query_id} reaches a terminal status",
            )
            last["queryId"] = query_id
            if last.get("status") == "Complete" and last.get("results"):
                return last
            time.sleep(5.0)
        raise AssertionError(
            f"query {query_string!r} never returned rows within {overall_timeout_s}s: {last!r}"
        )

    # --- 1. stats count(*) by <discovered JSON field>, sorted by the aggregate.
    grouped = _run_query("stats count(*) as n by level | sort n desc")
    assert grouped["status"] == "Complete", grouped["status"]
    rows = [_row_map(r) for r in grouped["results"]]
    assert len(rows) == 2, (
        f"stats ... by level must return one row per distinct level (2), got {rows!r}"
    )
    assert set(rows[0]) == {"level", "n"}, (
        "an aggregate row's fields are the 'by' key and the aliased aggregate only, got "
        f"{sorted(rows[0])!r}"
    )
    assert rows[0] == {"level": "ERROR", "n": "3"}, (
        f"expected ERROR/3 first under 'sort n desc', got {rows[0]!r}"
    )
    assert rows[1] == {"level": "INFO", "n": "2"}, (
        f"expected INFO/2 second under 'sort n desc', got {rows[1]!r}"
    )

    # --- 2. The statistics block is populated and internally consistent.
    stats = grouped.get("statistics")
    assert isinstance(stats, dict), f"GetQueryResults must return a statistics block: {grouped!r}"
    assert stats.get("recordsMatched") == 5.0, (
        f"recordsMatched must count the 5 seeded events, got {stats!r}"
    )
    assert stats.get("recordsScanned", 0) >= 5.0, (
        f"recordsScanned must be at least recordsMatched, got {stats!r}"
    )
    assert stats.get("bytesScanned", 0) > 0, (
        f"bytesScanned must be non-zero for a query that scanned records, got {stats!r}"
    )

    # --- 3. A grand-total aggregate with no 'by' clause is a single row.
    total = _run_query("stats count(*) as total")
    total_rows = [_row_map(r) for r in total["results"]]
    assert total_rows == [{"total": "5"}], (
        f"'stats count(*) as total' must return exactly one row totalling 5, got {total_rows!r}"
    )

    # --- 4. GetQueryResults on a completed query is stable, not one-shot.
    replay = svc.get_query_results(queryId=grouped["queryId"])
    assert replay.get("status") == "Complete", (
        f"re-reading a completed query must stay Complete, got {replay.get('status')!r}"
    )
    assert [_row_map(r) for r in replay.get("results", [])] == rows, (
        "GetQueryResults must be idempotent for a completed query; second read returned "
        f"{[_row_map(r) for r in replay.get('results', [])]!r} vs {rows!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
