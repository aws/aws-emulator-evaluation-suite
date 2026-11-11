"""put-log-events-nonexistent-stream-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _now_ms() -> int:
    return int(time.time() * 1000)

def _assert_rejected(fn, expected_code, expected_message, what):
    try:
        result = fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        assert code == expected_code, f"{what}: expected {expected_code}, got {code}"
        message = exc.response.get("Error", {}).get("Message")
        assert message == expected_message, f"{what}: expected {expected_message!r}, got {message!r}"
        return
    raise AssertionError(
        f"{what}: expected {expected_code}, but the call SUCCEEDED and returned {result!r}"
    )

def _poll_events(fn, *, timeout_s=30.0, interval_s=2.0):
    """GetLogEvents lags PutLogEvents by a few seconds even for a stream that already exists, so
    a bare read right after a write is flaky. Bound-poll for the events to become visible instead
    of trusting an unconditional sleep."""
    deadline = time.monotonic() + timeout_s
    last = []
    while time.monotonic() < deadline:
        last = fn()
        if last:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"no log events observed within {timeout_s}s; last saw {last!r}")

CHECK = "put-log-events-nonexistent-stream-fails"
GROUP = 'log-events'
SERVICES = ['logs']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutLogEvents to a nonexistent stream gets ResourceNotFoundException and its exact message and
    creates no stream, while a sibling stream accepts the call; once the stream exists the identical
    call lands its event.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-events-missing-")
    svc.create_log_group(logGroupName=group, tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    ctx.on_cleanup(lambda _n=group: svc.put_log_group_deletion_protection(logGroupIdentifier=_n, deletionProtectionEnabled=False))

    control_stream = ctx.unique_name("sim2real-behav-stream-control-")
    svc.create_log_stream(logGroupName=group, logStreamName=control_stream)
    svc.put_log_events(
        logGroupName=group,
        logStreamName=control_stream,
        logEvents=[{"timestamp": _now_ms(), "message": "control"}],
    )
    control_events = _poll_events(
        lambda: svc.get_log_events(
            logGroupName=group, logStreamName=control_stream, startFromHead=True
        )["events"]
    )
    assert len(control_events) == 1 and control_events[0]["message"] == "control", (
        f"positive control: expected the control event to be readable back, got {control_events!r}"
    )

    stream = ctx.unique_name("sim2real-behav-stream-missing-")
    message = "put-log-events-nonexistent-stream-fails probe"
    _assert_rejected(
        lambda: svc.put_log_events(
            logGroupName=group,
            logStreamName=stream,
            logEvents=[{"timestamp": _now_ms(), "message": message}],
        ),
        "ResourceNotFoundException",
        "The specified log stream does not exist.",
        "PutLogEvents against a nonexistent stream",
    )

    described = svc.describe_log_streams(
        logGroupName=group, logStreamNamePrefix=stream
    )["logStreams"]
    assert described == [], (
        f"expected no stream to have been created by the rejected call, found {described!r}"
    )

    svc.create_log_stream(logGroupName=group, logStreamName=stream)
    svc.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": _now_ms(), "message": message}],
    )

    events = _poll_events(
        lambda: svc.get_log_events(
            logGroupName=group, logStreamName=stream, startFromHead=True
        )["events"]
    )
    assert len(events) == 1 and events[0]["message"] == message, (
        f"expected the identical call to succeed once the stream exists, got {events!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
