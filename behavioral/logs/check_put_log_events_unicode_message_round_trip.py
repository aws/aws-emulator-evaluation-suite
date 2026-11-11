"""put-log-events-unicode-message-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-log-events-unicode-message-round-trip"
GROUP = "representation"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A log event message with multi-byte unicode chars round-trips byte-for-byte via GetLogEvents."""
    logs = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-logs-")
    stream = "unicode-stream"

    logs.create_log_group(logGroupName=group, tags={"sim2real-behav": "put-log-events-unicode-message-round-trip"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    logs.create_log_stream(logGroupName=group, logStreamName=stream)

    # Mix of Latin accents, CJK, Cyrillic, Greek, RTL Arabic, and emoji.
    message = "café ☕ 日本語テスト Москва θήτα مرحبا 🎉🚀 em—dash"
    now_ms = int(time.time() * 1000)
    logs.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": now_ms, "message": message}],
    )

    events = _poll_for_events(ctx, group, stream, expected_count=1)
    assert len(events) == 1, f"expected exactly 1 event on {group}/{stream}, got {len(events)}: {events!r}"
    assert events[0]["message"] == message, (
        f"unicode message not preserved byte-for-byte: {events[0]['message']!r} != {message!r}"
    )


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
