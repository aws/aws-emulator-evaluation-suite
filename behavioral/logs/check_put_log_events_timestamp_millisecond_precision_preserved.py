"""put-log-events-timestamp-millisecond-precision-preserved."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-log-events-timestamp-millisecond-precision-preserved"
GROUP = "representation"
SERVICES = ["logs"]


def _delete_log_group(logs, name):
    """Teardown: delete the log group; ResourceNotFoundException means the body already deleted it."""
    try:
        logs.delete_log_group(logGroupName=name)
    except logs.exceptions.ResourceNotFoundException:
        return


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Event timestamps at millisecond precision are preserved exactly, with no rounding, and a
    deleted log group is genuinely gone rather than merely unlisted."""
    logs = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-logs-")
    stream = "timestamp-stream"

    logs.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: _delete_log_group(logs, group))
    logs.create_log_stream(logGroupName=group, logStreamName=stream)

    now_ms = int(time.time() * 1000)
    # Force a non-round millisecond remainder so second-level truncation would be detectable.
    precise_ms = (now_ms - (now_ms % 1000)) + 137
    logs.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": precise_ms, "message": "timestamp-precision-check"}],
    )

    events = _poll_for_events(ctx, group, stream, expected_count=1)
    assert len(events) == 1
    got_ts = events[0]["timestamp"]
    assert got_ts == precise_ms, f"timestamp not preserved exactly: {got_ts} != {precise_ms}"
    assert got_ts % 1000 == 137, "millisecond remainder was rounded/truncated"

    logs.delete_log_group(logGroupName=group)
    remaining = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])
    assert remaining == [], f"log group {group} still listed after delete: {remaining}"

    code, message = _error(
        lambda: logs.put_log_events(
            logGroupName=group,
            logStreamName=stream,
            logEvents=[{"timestamp": precise_ms, "message": "post-delete-probe"}],
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException writing to a deleted log group, got {code}"
    )
    assert message == "The specified log group does not exist.", f"unexpected not-found message {message!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("expected the call to fail, but it succeeded")


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
