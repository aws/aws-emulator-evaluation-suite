"""put-log-events-millisecond-timestamp-preserved."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-log-events-millisecond-timestamp-preserved"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An event timestamp written with exact millisecond precision comes back
    unchanged from GetLogEvents -- not rounded down to the second, not
    truncated, not shifted by any epoch/unit conversion bug."""
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-lg-")
    stream_name = ctx.unique_name("sim2real-behav-ls-")

    logs.create_log_group(logGroupName=group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))
    logs.create_log_stream(logGroupName=group_name, logStreamName=stream_name)

    # Build a timestamp that is "now" but forced to a non-round millisecond
    # offset (e.g. ...*1000 + 517) so a service that silently rounds to the
    # nearest second would be caught.
    now_ms = int(time.time() * 1000)
    exact_ms = (now_ms - (now_ms % 1000)) + 517
    message = "millisecond-precision-probe"
    logs.put_log_events(
        logGroupName=group_name,
        logStreamName=stream_name,
        logEvents=[{"timestamp": exact_ms, "message": message}],
    )

    events = _poll_for_events(ctx, group_name, stream_name, expected_count=1)
    assert len(events) == 1, f"expected exactly 1 event, got {len(events)}"
    assert events[0]["message"] == message, (
        f"message not preserved: sent {message!r} got {events[0]['message']!r}"
    )
    assert events[0]["timestamp"] == exact_ms, (
        f"timestamp not preserved exactly: sent {exact_ms} got {events[0]['timestamp']}"
    )


def _poll_for_events(ctx, group_name, stream_name, expected_count=1, timeout_s=30.0):
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    events = []
    while time.monotonic() < deadline:
        resp = logs.get_log_events(
            logGroupName=group_name,
            logStreamName=stream_name,
            startFromHead=True,
        )
        events = resp.get("events", [])
        if len(events) >= expected_count:
            return events
        time.sleep(1.0)
    raise AssertionError(
        f"expected {expected_count} events, got {len(events)} within {timeout_s}s"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
