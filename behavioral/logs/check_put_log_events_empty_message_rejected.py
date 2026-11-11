"""put-log-events-empty-message-rejected."""
from __future__ import annotations

import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-log-events-empty-message-rejected"
GROUP = "representation"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutLogEvents rejects an empty-string message with InvalidParameterException server-side and
    stores nothing, while one-character messages before and after are accepted and stored.
    """
    logs = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-logs-")
    stream = "empty-message-stream"

    logs.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    logs.create_log_stream(logGroupName=group, logStreamName=stream)

    base_ms = int(time.time() * 1000)

    logs.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": base_ms, "message": "x"}],
    )
    events = _poll_for_events(ctx, group, stream, expected_count=1)
    assert len(events) == 1 and events[0]["message"] == "x"

    # botocore validates minLength=1 client-side; disable it so the request reaches the service.
    unvalidated_logs = ctx.client(
        "logs", config=Config(parameter_validation=False, retries={"max_attempts": 1})
    )
    code, message = _client_error(
        lambda: unvalidated_logs.put_log_events(
            logGroupName=group,
            logStreamName=stream,
            logEvents=[{"timestamp": base_ms + 1, "message": ""}],
        )
    )
    assert code == "InvalidParameterException", f"unexpected error code: {code}"
    assert message == (
        "1 validation error detected: Value at 'logEvents.1.member.message' failed to satisfy "
        "constraint: Member must have length greater than or equal to 1"
    ), f"unexpected message: {message!r}"


    events_after = logs.get_log_events(
        logGroupName=group, logStreamName=stream, startFromHead=True, limit=100
    )["events"]
    assert len(events_after) == 1, f"empty message was stored despite rejection: {events_after}"
    assert events_after[0]["message"] == "x"

    logs.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": base_ms + 2, "message": "still-writable"}],
    )
    events_final = _poll_for_events(ctx, group, stream, expected_count=2)
    messages = sorted(e["message"] for e in events_final)
    assert messages == ["still-writable", "x"], messages


def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_for_events(ctx, group, stream, expected_count, timeout_s=20.0, interval_s=1.0):
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    events = []
    while time.monotonic() < deadline:
        resp = logs.get_log_events(
            logGroupName=group, logStreamName=stream, startFromHead=True, limit=100
        )
        events = resp.get("events", [])
        if len(events) >= expected_count:
            return events
        time.sleep(interval_s)
    raise AssertionError(
        f"expected {expected_count} events on {group}/{stream}, got {len(events)} after {timeout_s}s"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
