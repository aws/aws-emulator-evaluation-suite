"""logsquery-sort-on-a-parsed-number-orders-numerically."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "logsquery-sort-on-a-parsed-number-orders-numerically"
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


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A field from a ``parse`` regex named capture sorts as a number in both directions: ``sort lat
    desc`` over 9/25/100/200/300 returns 300 first and 9 last, unlike the lexicographic order.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-lqsortnum-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    marker = ctx.unique_name("mk")

    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)

    latencies = [100, 200, 300, 9, 25]
    base_ms = _now_ms()
    svc.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[
            {"timestamp": base_ms - (len(latencies) - i) * 1000,
             "message": f"REQ {marker} lat={lat}ms"}
            for i, lat in enumerate(latencies)
        ],
    )

    numeric_desc = [str(v) for v in sorted(latencies, reverse=True)]
    numeric_asc = [str(v) for v in sorted(latencies)]
    lexicographic_desc = sorted((str(v) for v in latencies), reverse=True)
    assert numeric_desc != lexicographic_desc, (
        "the seeded latencies must distinguish numeric from lexicographic order, but both give "
        f"{numeric_desc!r} -- fix the seed, not the assertion"
    )

    now_s = base_ms // 1000
    parse = f"filter @message like /{marker}/ | parse @message /lat=(?<lat>\\d+)ms/"

    desc = _await_rows(svc, group, f"{parse} | sort lat desc", now_s - 600, now_s + 120,
                       expect=len(latencies))
    got_desc = [_row_map(r).get("lat") for r in desc["results"]]
    assert got_desc == numeric_desc, (
        f"'sort lat desc' over a parsed field must order numerically as {numeric_desc!r}; got "
        f"{got_desc!r} (the lexicographic order of the same values is {lexicographic_desc!r})"
    )

    asc = _run_query(svc, group, f"{parse} | sort lat asc", now_s - 600, now_s + 120)
    got_asc = [_row_map(r).get("lat") for r in asc["results"]]
    assert got_asc == numeric_asc, (
        f"'sort lat asc' over a parsed field must order numerically as {numeric_asc!r}, got "
        f"{got_asc!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
