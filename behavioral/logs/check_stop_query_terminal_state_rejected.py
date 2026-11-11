"""stop-query-terminal-state-rejected."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-query-terminal-state-rejected"
GROUP = "state-machine"
SERVICES = ["logs"]


def _logs_refusal(text, code, message):
    """`text` with the suffix CloudWatch Logs appends to a refusal. Only the per-call request id is
    read from `message`, and only in its 36-character form."""
    found = re.search(r"; Request ID: ([0-9a-f-]{36}); Proxy: null\)$", message or "")
    request_id = found.group(1) if found else "<no request id>"
    return (
        f"{text} (Service: AWSLogs; Status Code: 400; Error Code: {code}; "
        f"Request ID: {request_id}; Proxy: null)"
    )


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StopQuery succeeds on a running query, but on a Complete query it is refused with
    InvalidParameterException and its message, and the query stays Complete.
    """
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-sqterm-")
    stream_name = "stream-1"
    logs.create_log_group(logGroupName=group_name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))
    logs.create_log_stream(logGroupName=group_name, logStreamName=stream_name)

    now_ms = int(time.time() * 1000)
    logs.put_log_events(
        logGroupName=group_name,
        logStreamName=stream_name,
        logEvents=[{"timestamp": now_ms, "message": "hello-stop-query-terminal"}],
    )
    start_time_s = (now_ms // 1000) - 300
    end_time_s = (now_ms // 1000) + 300

    # Positive control: stop a query immediately, while it is still running/scheduled. A query over
    # one event can finish before StopQuery arrives; then a fresh query is started, up to 5 times.
    for _attempt in range(5):
        control_query_id = logs.start_query(
            logGroupName=group_name,
            startTime=start_time_s,
            endTime=end_time_s,
            queryString="fields @timestamp, @message",
        )["queryId"]
        try:
            control_stop = logs.stop_query(queryId=control_query_id)
            break
        except ClientError as err:
            if not err.response["Error"].get("Message", "").startswith("Query is already ended"):
                raise
    else:
        raise AssertionError("every control query ended before StopQuery reached it")
    assert control_stop["success"] is True, (
        f"expected StopQuery to succeed on a running query, got {control_stop!r}"
    )
    control_result = _poll_until(
        lambda: logs.get_query_results(queryId=control_query_id),
        lambda r: r["status"] in ("Complete", "Failed", "Cancelled", "Timeout"),
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert control_result["status"] in ("Cancelled", "Complete"), (
        f"expected the stopped control query to reach a stopped terminal state, "
        f"got {control_result['status']!r}"
    )

    # The subject: a query that reaches its terminal state on its own.
    query_id = logs.start_query(
        logGroupName=group_name,
        startTime=start_time_s,
        endTime=end_time_s,
        queryString="fields @timestamp, @message",
    )["queryId"]

    result = _poll_until(
        lambda: logs.get_query_results(queryId=query_id),
        lambda r: r["status"] in ("Complete", "Failed", "Cancelled", "Timeout"),
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert result["status"] == "Complete", f"query ended in {result['status']!r}"

    # Stopping an already-terminal query is a state-conflict, not a no-op success.
    # Only the backend Request ID in the refusal message varies.
    code, message = _error(lambda: logs.stop_query(queryId=query_id))
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    expected = _logs_refusal("Query is already ended with Complete", "InvalidParameterException", message)
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The rejected stop must have had no effect: an independent read still shows Complete.
    after = logs.get_query_results(queryId=query_id)
    assert after["status"] == "Complete", (
        f"rejected StopQuery must not change query state, but status is now {after['status']!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


def _error(fn):
    try:
        response = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {response!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
