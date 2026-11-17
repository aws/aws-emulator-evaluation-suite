"""put-log-events-embedded-control-characters-round-trip-as-one-event."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-log-events-embedded-control-characters-round-trip-as-one-event"
GROUP = "representation"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A single log event whose message embeds newlines, tabs and a carriage return round-trips
    byte-for-byte via GetLogEvents and is never split into several events.
    """
    logs = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-logs-ctl-")
    stream = "control-char-stream"

    logs.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    logs.create_log_stream(logGroupName=group, logStreamName=stream)

    # A multi-line stack trace is the realistic shape a customer sends as ONE event.
    message = "ERROR: boom\n  at inner()\tindented-with-a-tab\r\n  at outer()"
    now_ms = int(time.time() * 1000)
    logs.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": now_ms, "message": message}],
    )

    events = _poll_for_events(logs, group, stream, expected_count=1)
    assert len(events) == 1, (
        f"a message with embedded newlines must stay one event, got {len(events)}: {events!r}"
    )
    assert events[0]["message"] == message, (
        f"control characters not preserved byte-for-byte: {events[0]['message']!r} != {message!r}"
    )


def _poll_for_events(logs, group, stream, expected_count, timeout_s=20.0, interval_s=1.0):
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
        f"expected {expected_count} event(s) on {group}/{stream}, got {len(events)} after {timeout_s}s"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
