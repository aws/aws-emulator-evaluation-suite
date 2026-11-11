"""logs-insights-semantics-stop-running-query-reports-cancelled."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "logs-insights-semantics-stop-running-query-reports-cancelled"
GROUP = 'insights'
SERVICES = ['logs']


_TERMINAL = ("Complete", "Failed", "Cancelled", "Timeout", "Unknown")


def _logs_refusal(text, code, message):
    """`text` with the suffix CloudWatch Logs appends to a refusal. Only the per-call request id is
    read from `message`, and only in its 36-character form."""
    found = re.search(r"; Request ID: ([0-9a-f-]{36}); Proxy: null\)$", message or "")
    request_id = found.group(1) if found else "<no request id>"
    return (
        f"{text} (Service: AWSLogs; Status Code: 400; Error Code: {code}; "
        f"Request ID: {request_id}; Proxy: null)"
    )


def _put(svc, group, stream, events):
    svc.create_log_stream(logGroupName=group, logStreamName=stream)
    svc.put_log_events(
        logGroupName=group, logStreamName=stream,
        logEvents=sorted(events, key=lambda e: e["timestamp"]),
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the check's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the check's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_terminal(svc, qid, *, timeout_s=120, ctx=None):
    seen = []
    deadline = time.monotonic() + timeout_s
    while True:
        resp = svc.get_query_results(queryId=qid)
        if not seen or seen[-1] != resp["status"]:
            seen.append(resp["status"])
        if resp["status"] in _TERMINAL:
            return resp, seen
        if time.monotonic() > deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"query {qid} to reach a terminal status: the run budget ended first; not graded")
            raise AssertionError(f"query {qid} never reached a terminal status; saw {seen!r}")
        time.sleep(0.5)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StopQuery on a running query returns success, and the query then reports exactly Cancelled
    in GetQueryResults and DescribeQueries and stays there; a second StopQuery also returns success.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-lisem-stop-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: svc.delete_log_group(logGroupName=group))
    now_ms = int(time.time() * 1000)
    _put(svc, group, "s", [{"timestamp": now_ms - 60_000 + i * 10, "message": f"line {i} " + "x" * 200}
                           for i in range(500)])
    # A wide window and a sort keep the query busy for longer than one round trip.
    start_s, end_s = int(time.time()) - 14 * 86400, int(time.time()) + 60

    accepted = None
    refusals = []
    # A query that finishes before the stop lands gets InvalidParameterException; retry fresh.
    for _ in range(6):
        qid = svc.start_query(logGroupNames=[group], startTime=start_s, endTime=end_s,
                              queryString="fields @message | sort @timestamp desc")["queryId"]
        try:
            resp = svc.stop_query(queryId=qid)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            # The ending status depends on the race and the backend Request ID varies.
            assert code == "InvalidParameterException", (
                f"a stop that lost the race to completion must be InvalidParameterException, got {code!r}"
            )
            message = exc.response["Error"].get("Message") or ""
            refusals.append(qid)
            ended, _ = _poll_terminal(svc, qid, timeout_s=_budget_s(ctx, 120), ctx=ctx)
            expected = _logs_refusal(
                f"Query is already ended with {ended['status']}", "InvalidParameterException", message
            )
            assert message == expected, f"expected StopQuery refusal {expected!r}, got {message!r}"
            continue
        assert resp.get("success") is True, (
            f"StopQuery on a running query must return success=True, got {resp!r}"
        )
        accepted = qid
        break
    assert accepted, f"no StopQuery was accepted in 6 attempts; every query finished first: {refusals!r}"

    final, seen = _poll_terminal(svc, accepted, timeout_s=_budget_s(ctx, 120), ctx=ctx)
    assert final["status"] == "Cancelled", (
        f"an accepted StopQuery must drive the query to Cancelled, saw {seen!r}"
    )
    assert "Complete" not in seen, f"a stopped query must not report Complete at any point: {seen!r}"

    described = {}
    for page in svc.get_paginator("describe_queries").paginate(logGroupName=group):
        for qd in page["queries"]:
            described[qd["queryId"]] = qd["status"]
    assert described.get(accepted) == "Cancelled", (
        f"DescribeQueries must report the stopped query Cancelled, got {described.get(accepted)!r}"
    )

    # Terminal state is sticky: a later read still reports Cancelled.
    again = svc.get_query_results(queryId=accepted)["status"]
    assert again == "Cancelled", f"Cancelled must be terminal, a later read returned {again!r}"

    # Re-stopping a Cancelled query is idempotent on real AWS (unlike stopping a Complete one,
    # which is refused): success=True again, and the state does not move off Cancelled.
    again_resp = svc.stop_query(queryId=accepted)
    assert again_resp.get("success") is True, f"re-stopping a Cancelled query must return success=True, got {again_resp!r}"
    after = svc.get_query_results(queryId=accepted)["status"]
    assert after == "Cancelled", f"a second StopQuery must leave the query Cancelled, got {after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
