"""logs-insights-get-query-results-query-id-is-a-durable-snapshot-handle."""

from __future__ import annotations

import json
import re
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "logs-insights-get-query-results-query-id-is-a-durable-snapshot-handle"
GROUP = "insights"
SERVICES = ["logs"]


_TERMINAL = ("Complete", "Failed", "Cancelled", "Timeout", "Unknown")
_QUERY = "fields n | sort n asc | limit 3"
_OVERLONG_ID = ("InvalidParameterException", "Query id is blank or exceeded max length 256")


def _unknown_id_results(query_id):
    """GetQueryResults' refusal of a queryId it never issued."""
    return "InvalidParameterException", f"The provided queryId = {query_id} is invalid "


def _unknown_id_stop(query_id):
    """StopQuery's refusal of a queryId it never issued."""
    return "ResourceNotFoundException", f"The provided queryId={query_id} is invalid."


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


def _query(ctx, svc, group, window, query, deadline=None):
    """Start `query`, poll it to a terminal status, which must be Complete; return (queryId, response)."""
    qid = svc.start_query(
        logGroupName=group, startTime=window[0], endTime=window[1], queryString=query
    )["queryId"]
    stop = time.monotonic() + _budget(ctx, 60)
    stop = stop if deadline is None else min(stop, deadline)
    while True:
        resp = svc.get_query_results(queryId=qid)
        if resp["status"] in _TERMINAL:
            assert resp["status"] == "Complete", f"{query!r} ended {resp['status']!r}: {resp!r}"
            return qid, resp
        if time.monotonic() > stop:
            raise AssertionError(f"{query!r} ({qid}) never reached a terminal status: {resp!r}")
        time.sleep(1)


def _query_until(ctx, svc, group, window, query, matched, *, cap_s=240, reserve_s=30):
    """Re-run `query` every 3 s until recordsMatched equals `matched`: ingestion into a new group is
    eventually consistent. Only that final terminal response is returned and graded."""
    deadline = time.monotonic() + _budget(ctx, cap_s, reserve_s)
    while True:
        qid, resp = _query(ctx, svc, group, window, query, deadline)
        if resp["statistics"]["recordsMatched"] == float(matched):
            return qid, resp
        left = deadline - time.monotonic()
        if left <= 0:
            raise AssertionError(
                f"{query!r} never matched {matched} records: {resp['statistics']!r}"
            )
        time.sleep(min(3.0, left))


def _rows(resp):
    """Each row's projected fields as (field, value) pairs, leaving out the opaque @ptr."""
    return [
        [(e["field"], e["value"]) for e in row if e["field"] != "@ptr"] for row in resp["results"]
    ]


@tags(
    "axis:rejection",
    "cap:c2",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """GetQueryResults refuses an unknown queryId with InvalidParameterException where StopQuery says
    ResourceNotFoundException; an issued queryId returns the same rows and statistics after its log
    group is deleted, and GetLogRecord on a row's @ptr still returns that event."""
    svc = ctx.client("logs")
    unknown = str(uuid.uuid4())
    for bad in (unknown, "not-a-query-id"):
        expect_error(lambda bad=bad: svc.get_query_results(queryId=bad), *_unknown_id_results(bad))
    expect_error(lambda: svc.get_query_results(queryId="a" * 257), *_OVERLONG_ID)
    expect_error(lambda: svc.stop_query(queryId=unknown), *_unknown_id_stop(unknown))

    group = ctx.unique_name("sim2real-lisem-gqr-snapshot-")
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

    qid, snap = _query_until(ctx, svc, group, window, _QUERY, 12)
    assert _rows(snap) == [[("n", str(i))] for i in range(3)], (
        f"{_QUERY!r} returned rows {_rows(snap)!r}, expected n 0, 1, 2"
    )
    ptr = next(e["value"] for e in snap["results"][0] if e["field"] == "@ptr")
    record = svc.get_log_record(logRecordPointer=ptr)["logRecord"]
    got = (record.get("@message"), record.get("@timestamp"))
    assert got == (json.dumps({"n": 0}), str(t0_s * 1000)), (
        f"GetLogRecord on row 0's @ptr returned {record!r}, expected event 0's message, timestamp"
    )

    svc.delete_log_group(logGroupName=group)
    after = svc.get_query_results(queryId=qid)
    assert after["status"] == "Complete", (
        f"after deleting the group, {qid} reports {after['status']!r}"
    )
    assert _rows(after) == _rows(snap), (
        f"after deleting the group, {qid} returned rows {_rows(after)!r}, expected {_rows(snap)!r}"
    )
    assert after["statistics"] == snap["statistics"], (
        f"after deleting the group, {qid} reports {after['statistics']!r}, expected {snap['statistics']!r}"
    )

    kept = svc.get_log_record(logRecordPointer=ptr)["logRecord"]
    got = (kept.get("@message"), kept.get("@timestamp"))
    assert got == (json.dumps({"n": 0}), str(t0_s * 1000)), (
        f"after deleting the group, GetLogRecord on row 0's @ptr returned {kept!r}, "
        "expected event 0's message, timestamp"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
