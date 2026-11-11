"""query-lifecycle-state-ordering."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-lifecycle-state-ordering"
GROUP = 'insights'
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


def _make_events(messages, start_ts_ms=None, step_ms=1000):
    base = start_ts_ms if start_ts_ms is not None else int(time.time() * 1000)
    return [{"timestamp": base + i * step_ms, "message": m} for i, m in enumerate(messages)]


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _describe_query_status(svc, query_id):
    for q in svc.describe_queries().get("queries", []):
        if q.get("queryId") == query_id:
            return q.get("status")
    return None


def _wait_query_terminal(svc, query_id, *, timeout_s=90, interval_s=2.0):
    return _poll_until(
        lambda: svc.get_query_results(queryId=query_id),
        lambda r: r.get("status") in ("Complete", "Failed", "Cancelled", "Timeout"),
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"query {query_id} reaches a terminal status",
    )


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A query moves through Scheduled/Running to Complete in both DescribeQueries and GetQueryResults;
    StopQuery on a second query either succeeds or is refused as already ended, and both APIs then
    report the same Cancelled or Complete status.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-qlifecycle-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)
    svc.put_log_events(
        logGroupName=group, logStreamName=stream, logEvents=_make_events(["lifecycle-probe-event"])
    )

    now = int(time.time())

    # --- Part 1: a query is allowed to run to completion, and DescribeQueries
    # + GetQueryResults agree on its terminal status throughout. ---
    start_resp = svc.start_query(
        logGroupName=group,
        startTime=now - 3600,
        endTime=now + 3600,
        queryString="fields @timestamp, @message | limit 10",
    )
    query_id = start_resp["queryId"]

    status_seen = _describe_query_status(svc, query_id)
    assert status_seen in (None, "Scheduled", "Running", "Complete"), (
        f"unexpected initial DescribeQueries status: {status_seen!r}"
    )

    result = _wait_query_terminal(svc, query_id)
    assert result["status"] == "Complete", f"expected the query to complete, got {result['status']!r}"

    final_status = _poll_until(
        lambda: _describe_query_status(svc, query_id),
        lambda s: s in ("Complete", "Failed", "Cancelled", "Timeout"),
        timeout_s=30,
        interval_s=2.0,
        description="DescribeQueries converges to the same terminal status",
    )
    assert final_status == "Complete", (
        f"DescribeQueries and GetQueryResults disagree on terminal status: "
        f"DescribeQueries={final_status!r}, GetQueryResults={result['status']!r}"
    )

    # --- Part 2: StopQuery halts a second, independent query in-flight. ---
    start_resp_2 = svc.start_query(
        logGroupName=group,
        startTime=now - 3600,
        endTime=now + 3600,
        queryString="fields @timestamp, @message | limit 10",
    )
    query_id_2 = start_resp_2["queryId"]

    # StopQuery either reports success, or (if the query legitimately raced to
    # completion first) fails with a specific "already ended" error — never a
    # generic/opaque failure.
    stop_message = None
    try:
        stop_resp = svc.stop_query(queryId=query_id_2)
    except ClientError as exc:
        stop_code = exc.response.get("Error", {}).get("Code")
        # The ending status depends on the race and the backend Request ID varies.
        assert stop_code == "InvalidParameterException", (
            f"expected StopQuery on a raced-to-completion query to fail with "
            f"InvalidParameterException, got {stop_code!r}"
        )
        stop_message = exc.response.get("Error", {}).get("Message") or ""
    else:
        assert isinstance(stop_resp.get("success"), bool), (
            f"expected StopQuery's success field to be a boolean, got {stop_resp.get('success')!r}"
        )

    result_2 = _wait_query_terminal(svc, query_id_2)
    if stop_message is not None:
        # A refused stop names the status the query had already ended with.
        expected = _logs_refusal(
            f"Query is already ended with {result_2['status']}", "InvalidParameterException", stop_message
        )
        assert stop_message == expected, f"expected StopQuery refusal {expected!r}, got {stop_message!r}"
    assert result_2["status"] in ("Cancelled", "Complete"), (
        f"expected the stopped query to end Cancelled (or have raced to Complete), got {result_2['status']!r}"
    )
    status_2_describe = _describe_query_status(svc, query_id_2)
    assert status_2_describe == result_2["status"], (
        f"DescribeQueries ({status_2_describe!r}) and GetQueryResults ({result_2['status']!r}) "
        f"disagree on the stopped query's terminal status"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
