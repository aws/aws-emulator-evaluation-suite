"""logsquery-window-ending-before-group-creation-rejected."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "logsquery-window-ending-before-group-creation-rejected"
GROUP = 'insights-query'
SERVICES = ['logs']


def _logs_refusal(text, code, message):
    """`text` with the suffix CloudWatch Logs appends to a refusal. Only the per-call request id is
    read from `message`, and only in its 36-character form."""
    found = re.search(r"; Request ID: ([0-9a-f-]{36}); Proxy: null\)$", message or "")
    request_id = found.group(1) if found else "<no request id>"
    return (
        f"{text} (Service: AWSLogs; Status Code: 400; Error Code: {code}; "
        f"Request ID: {request_id}; Proxy: null)"
    )


def _now_ms() -> int:
    return int(time.time() * 1000)


def _row_map(row):
    return {f["field"]: f["value"] for f in row}


def _error_code(fn):
    """The AWS (code, message) fn() raised. An unexpected SUCCESS raises, so a target that
    accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"the call was expected to be refused but it succeeded, returning {result!r}")


def _all_queries(svc, group):
    """Every query DescribeQueries knows about for this log group, across all pages."""
    out, token = [], None
    while True:
        kw = {"logGroupName": group}
        if token:
            kw["nextToken"] = token
        page = svc.describe_queries(**kw)
        out.extend(page.get("queries", []))
        token = page.get("nextToken")
        if not token:
            return out


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


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """StartQuery over a window ending before the log group was created is rejected with
    MalformedQueryException and creates no query, even though a seeded event lies inside it;
    moving only endTime past creation returns that event."""
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-lqwincreate-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    marker = ctx.unique_name("mk")

    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)

    base_ms = _now_ms()
    # 25 minutes old: inside the rejected window below, and inside the accepted one.
    svc.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": base_ms - 1500 * 1000, "message": f"WINDOW {marker} slot=old"}],
    )

    now_s = base_ms // 1000
    query = f"fields @message | filter @message like /{marker}/"

    # The window [-40min, -20min] contains the seeded event but ends ~20 minutes before the log
    # group existed; a target that answered at all would have a row to return.
    code, code_msg = _error_code(
        lambda: svc.start_query(
            logGroupNames=[group],
            startTime=now_s - 2400,
            endTime=now_s - 1200,
            queryString=query,
        )
    )
    # Only the internal Request ID at the end of the message varies; the response does not expose it.
    assert code == "MalformedQueryException", (
        f"a query window ending before the log group's creation time must be rejected with "
        f"MalformedQueryException, got {code!r}"
    )
    # The span is an offset into the service's rewritten query text, so it is read from the message.
    text = (
        "Query's end date and time is either before the log groups creation time or exceeds the "
        "log groups log retention settings "
    )
    span = re.match(re.escape(text) + r"(\(\[\d+,\d+\]\)) ", code_msg or "")
    expected = _logs_refusal(
        text + (span.group(1) if span else "<no span>"), "MalformedQueryException", code_msg
    )
    assert code_msg == expected, f"expected message {expected!r}, got {code_msg!r}"

    # Effect-absent: the rejected call left no query behind for the group.
    queries = _all_queries(svc, group)
    assert queries == [], (
        f"a rejected StartQuery must not create a query on the log group, got {queries!r}"
    )

    # Positive control: the same query text, endTime moved past the creation time, returns the
    # event that the rejected window also contained.
    ok = _await_rows(svc, group, query, now_s - 2400, now_s + 120, expect=1)
    row = _row_map(ok["results"][0])
    assert row.get("@message") == f"WINDOW {marker} slot=old", (
        f"the positive control must return the seeded event, got {row!r}"
    )
    after = _all_queries(svc, group)
    assert after, (
        "the accepted query must be visible on the log group, which is what makes the empty "
        f"DescribeQueries above evidence of the rejection; got {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
