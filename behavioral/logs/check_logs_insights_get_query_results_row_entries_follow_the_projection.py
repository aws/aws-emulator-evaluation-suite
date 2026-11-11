"""logs-insights-get-query-results-row-entries-follow-the-projection."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "logs-insights-get-query-results-row-entries-follow-the-projection"
GROUP = "insights"
SERVICES = ["logs"]


_TERMINAL = ("Complete", "Failed", "Cancelled", "Timeout", "Unknown")


def _budget(ctx, cap_s, reserve_s=5.0):
    """A wait's cap, cut to the runner's remaining time so the check fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - reserve_s))


def _delete_group(svc, group):
    try:
        svc.delete_log_group(logGroupName=group)
    except svc.exceptions.ResourceNotFoundException:
        pass


def _query(ctx, svc, group, window, query, deadline=None):
    """Start `query` and poll GetQueryResults to a terminal status, which must be Complete."""
    qid = svc.start_query(
        logGroupName=group, startTime=window[0], endTime=window[1], queryString=query
    )["queryId"]
    stop = time.monotonic() + _budget(ctx, 60)
    stop = stop if deadline is None else min(stop, deadline)
    while True:
        resp = svc.get_query_results(queryId=qid)
        if resp["status"] in _TERMINAL:
            assert resp["status"] == "Complete", f"{query!r} ended {resp['status']!r}: {resp!r}"
            return resp
        if time.monotonic() > stop:
            raise AssertionError(f"{query!r} ({qid}) never reached a terminal status: {resp!r}")
        time.sleep(1)


def _query_until(ctx, svc, group, window, query, matched, *, cap_s=240, reserve_s=30):
    """Re-run `query` every 3 s until recordsMatched equals `matched`: ingestion into a new group is
    eventually consistent. Only that final terminal response is returned and graded."""
    deadline = time.monotonic() + _budget(ctx, cap_s, reserve_s)
    while True:
        resp = _query(ctx, svc, group, window, query, deadline)
        if resp["statistics"]["recordsMatched"] == float(matched):
            return resp
        left = deadline - time.monotonic()
        if left <= 0:
            raise AssertionError(
                f"{query!r} never matched {matched} records: {resp['statistics']!r}"
            )
        time.sleep(min(3.0, left))


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c3",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """GetQueryResults lists each row's fields in the order the query projects them, with @ptr last;
    a stats row lists the by-keys and then the aggregates in written order, with no @ptr.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-lisem-gqr-order-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: _delete_group(svc, group))
    svc.create_log_stream(logGroupName=group, logStreamName="s")
    # Events stamped before the group existed are never visible to Insights.
    t0_s = int(time.time()) + 1
    svc.put_log_events(
        logGroupName=group,
        logStreamName="s",
        logEvents=[
            {"timestamp": (t0_s + i) * 1000, "message": json.dumps({"n": i, "k": "ab"[i % 2]})}
            for i in range(12)
        ],
    )
    window = (t0_s - 60, t0_s + 600)

    fwd = _query_until(ctx, svc, group, window, "fields n, k, @timestamp | sort n asc", 12)
    assert len(fwd["results"]) == 12, (
        f"fields n, k, @timestamp: expected 12 rows, got {fwd['results']!r}"
    )
    for i, row in enumerate(fwd["results"]):
        names = [e["field"] for e in row]
        assert names == ["n", "k", "@timestamp", "@ptr"], (
            f"fields n, k, @timestamp: row {i} lists {names!r}, expected n, k, @timestamp, @ptr"
        )
        assert row[0]["value"] == str(i) and row[1]["value"] == "ab"[i % 2], (
            f"fields n, k, @timestamp: row {i} carries {row[:2]!r}, expected n={i}, k={'ab'[i % 2]}"
        )

    rev = _query(ctx, svc, group, window, "fields @timestamp, k, n | sort n asc")
    assert len(rev["results"]) == 12, (
        f"fields @timestamp, k, n: expected 12 rows, got {rev['results']!r}"
    )
    for i, row in enumerate(rev["results"]):
        names = [e["field"] for e in row]
        assert names == ["@timestamp", "k", "n", "@ptr"], (
            f"fields @timestamp, k, n: row {i} lists {names!r}, expected @timestamp, k, n, @ptr"
        )
        assert row[2]["value"] == str(i), f"fields @timestamp, k, n: row {i} carries {row!r}"

    by_key = _query(ctx, svc, group, window, "stats count(*) as c by k | sort k asc")["results"]
    assert by_key == [
        [{"field": "k", "value": "a"}, {"field": "c", "value": "6"}],
        [{"field": "k", "value": "b"}, {"field": "c", "value": "6"}],
    ], f"stats count(*) as c by k: expected rows [k, c] for a and b with no @ptr, got {by_key!r}"

    totals = _query(ctx, svc, group, window, "stats count(*) as c, max(n) as mx")["results"]
    assert totals == [[{"field": "c", "value": "12"}, {"field": "mx", "value": "11"}]], (
        f"stats count(*) as c, max(n) as mx: expected one row [c=12, mx=11] with no @ptr, got {totals!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
