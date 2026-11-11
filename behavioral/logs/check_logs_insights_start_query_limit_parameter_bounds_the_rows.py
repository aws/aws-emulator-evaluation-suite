"""logs-insights-start-query-limit-parameter-bounds-the-rows."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "logs-insights-start-query-limit-parameter-bounds-the-rows"
GROUP = "insights"
SERVICES = ["logs"]


_TERMINAL = ("Complete", "Failed", "Cancelled", "Timeout", "Unknown")
_QUERY = "fields n | sort n asc"
_LIMIT_TOO_LARGE = (
    "InvalidParameterException",
    "1 validation error detected: Value at 'limit' failed to satisfy constraint: "
    "Member must have value less than or equal to 100000",
)


def _budget(ctx, cap_s, reserve_s=5.0):
    """A wait's cap, cut to the runner's remaining time so the check fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - reserve_s))


def _delete_group(svc, group):
    try:
        svc.delete_log_group(logGroupName=group)
    except svc.exceptions.ResourceNotFoundException:
        pass


def expect_error(fn, code, message):
    """Assert fn() is refused with exactly (code, message); `<id>` in message stands for the per-call
    request id CloudWatch Logs appends, read from the refusal only in its 36-character form."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        got = (err.get("Code"), err.get("Message"))
    else:
        raise AssertionError(
            f"expected {code!r} {message!r}, but the call SUCCEEDED and returned {result!r}"
        )
    found = re.search(r"; Request ID: ([0-9a-f-]{36}); Proxy: null\)$", got[1] or "")
    want = (code, message.replace("<id>", found.group(1) if found else "<no request id>"))
    assert got == want, f"expected {want!r}, got {got!r}"


def _query(ctx, svc, group, window, query, deadline=None, **start_kw):
    """Start `query` and poll GetQueryResults to a terminal status, which must be Complete."""
    qid = svc.start_query(
        logGroupName=group, startTime=window[0], endTime=window[1], queryString=query, **start_kw
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


def _ns(resp):
    return [row[0]["value"] for row in resp["results"]]


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """StartQuery's limit caps the returned rows and overrides a `| limit` command in either direction,
    and a limit above 100000 is refused."""
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-lisem-gqr-limit-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: _delete_group(svc, group))
    svc.create_log_stream(logGroupName=group, logStreamName="s")
    # Events stamped before the group existed are never visible to Insights.
    t0_s = int(time.time()) + 1
    svc.put_log_events(
        logGroupName=group,
        logStreamName="s",
        logEvents=[
            {"timestamp": (t0_s + i) * 1000, "message": json.dumps({"n": i})} for i in range(12)
        ],
    )
    window = (t0_s - 60, t0_s + 600)

    full = _query_until(ctx, svc, group, window, _QUERY, 12)
    assert _ns(full) == [str(i) for i in range(12)], (
        f"{_QUERY!r} without a limit returned n {_ns(full)!r}"
    )

    capped = _query(ctx, svc, group, window, _QUERY, limit=3)
    assert _ns(capped) == ["0", "1", "2"], f"limit=3 returned n {_ns(capped)!r}, expected 0, 1, 2"
    stats = capped["statistics"]
    assert (stats["resultCount"], stats["recordsMatched"]) == (3.0, 12.0), (
        f"limit=3 reported resultCount/recordsMatched {stats!r}, expected 3 of 12 matched"
    )

    wider = _query(ctx, svc, group, window, f"{_QUERY} | limit 2", limit=5)
    assert _ns(wider) == ["0", "1", "2", "3", "4"], (
        f"limit=5 with '| limit 2' returned n {_ns(wider)!r}, expected the parameter's 5 rows 0..4"
    )
    narrower = _query(ctx, svc, group, window, f"{_QUERY} | limit 5", limit=3)
    assert _ns(narrower) == ["0", "1", "2"], (
        f"limit=3 with '| limit 5' returned n {_ns(narrower)!r}, expected the parameter's 3 rows 0..2"
    )

    expect_error(
        lambda: svc.start_query(
            logGroupName=group,
            startTime=window[0],
            endTime=window[1],
            queryString=_QUERY,
            limit=100001,
        ),
        *_LIMIT_TOO_LARGE,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
