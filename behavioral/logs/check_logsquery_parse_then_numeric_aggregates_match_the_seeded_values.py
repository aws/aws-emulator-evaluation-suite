"""logsquery-parse-then-numeric-aggregates-match-the-seeded-values."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "logsquery-parse-then-numeric-aggregates-match-the-seeded-values"
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
    """Grouping by a parsed string field and aggregating a parsed numeric field returns sum/avg/max/min
    and counts equal to arithmetic over the seeded values, with recordsMatched counting every event.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-lqaggregate-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    marker = ctx.unique_name("mk")

    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)

    seeded = [("alpha", 100), ("alpha", 200), ("alpha", 300), ("beta", 9), ("beta", 25)]
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

    # What the rows MUST say, computed from the seed rather than written out twice.
    want = {}
    for name, lat in seeded:
        want.setdefault(name, []).append(lat)
    expected = [
        {"svc": name,
         "total": str(sum(v)), "mean": str(sum(v) // len(v)),
         "peak": str(max(v)), "low": str(min(v)), "n": str(len(v))}
        for name, v in sorted(want.items())
    ]

    now_s = base_ms // 1000
    query = (
        f"filter @message like /{marker}/"
        ' | parse @message "svc=* lat=* status=*" as svc, lat, st'
        " | stats sum(lat) as total, avg(lat) as mean, max(lat) as peak, min(lat) as low,"
        " count(*) as n by svc"
        " | sort svc asc"
    )
    res = _await_rows(svc, group, query, now_s - 600, now_s + 120, expect=len(expected))

    rows = [_row_map(r) for r in res["results"]]
    assert rows == expected, (
        f"aggregate rows must be arithmetic over the seeded latencies {seeded!r}: "
        f"expected {expected!r}, got {rows!r}"
    )

    # An aggregate row is NOT a log event: it carries only the 'by' key and the aliases, so the
    # implicit @ptr/@message of a projection row must be absent.
    assert set(rows[0]) == {"svc", "total", "mean", "peak", "low", "n"}, (
        "an aggregate row's fields are the 'by' key and the aliased aggregates only, got "
        f"{sorted(rows[0])!r}"
    )

    stats = res.get("statistics") or {}
    assert stats.get("recordsMatched") == float(len(seeded)), (
        f"recordsMatched must count the {len(seeded)} seeded events even though the query returned "
        f"{len(rows)} aggregate rows, got {stats.get('recordsMatched')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
