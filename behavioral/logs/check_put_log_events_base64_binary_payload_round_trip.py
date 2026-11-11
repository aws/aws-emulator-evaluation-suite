"""put-log-events-base64-binary-payload-round-trip."""
from __future__ import annotations

import base64
import os
import time

from behavioral_harness import tags

CHECK = "put-log-events-base64-binary-payload-round-trip"
GROUP = "representation"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A base64-encoded binary blob embedded in a log event message round-trips unchanged."""
    logs = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-logs-")
    stream = "binary-stream"

    logs.create_log_group(logGroupName=group, tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    logs.create_log_stream(logGroupName=group, logStreamName=stream)

    raw_bytes = os.urandom(256)
    encoded = base64.b64encode(raw_bytes).decode("ascii")
    message = f"binary-payload:{encoded}"
    now_ms = int(time.time() * 1000)
    logs.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": now_ms, "message": message}],
    )

    events = _poll_for_events(ctx, group, stream, expected_count=1)
    assert len(events) == 1, f"expected exactly 1 event, got {len(events)}: {events!r}"
    got_message = events[0]["message"]
    assert got_message == message, f"message not preserved: {got_message!r} != {message!r}"

    got_encoded = got_message.split("binary-payload:", 1)[1]
    got_bytes = base64.b64decode(got_encoded)
    assert got_bytes == raw_bytes, "decoded binary payload differs from what was written"


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
