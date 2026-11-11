"""put-log-events-future-timestamp-skew-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-log-events-future-timestamp-skew-rejected"
GROUP = "ordering"
SERVICES = ["logs"]


@tags("axis:negative-delivery", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An event more than 2 hours in the future is reported via tooNewLogEventStartIndex and never
    stored, while valid events in the same and a follow-up batch are stored.
    """
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-logs-skew-")
    stream_name = "primary"

    logs.create_log_group(logGroupName=group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))
    logs.create_log_stream(logGroupName=group_name, logStreamName=stream_name)

    now_ms = int(time.time() * 1000)
    valid_ts = now_ms
    future_ts = now_ms + 3 * 60 * 60 * 1000  # 3 hours ahead: past the 2-hour boundary

    resp = logs.put_log_events(
        logGroupName=group_name,
        logStreamName=stream_name,
        logEvents=[
            {"timestamp": valid_ts, "message": "valid-event"},
            {"timestamp": future_ts, "message": "future-event"},
        ],
    )

    rejected = resp.get("rejectedLogEventsInfo")
    assert rejected is not None, "expected rejectedLogEventsInfo for a too-far-future event"
    assert rejected.get("tooNewLogEventStartIndex") == 1, (
        "tooNewLogEventStartIndex is INCLUSIVE and the future event is at batch index 1, "
        f"expected 1, got {rejected!r}"
    )
    assert "tooOldLogEventEndIndex" not in rejected, (
        f"a too-NEW event must not also be reported as too old: {rejected!r}"
    )

    messages = _poll_until(
        lambda: _all_messages(logs, group_name, stream_name),
        lambda msgs: "valid-event" in msgs,
        timeout_s=30.0,
        interval_s=1.5,
    )
    assert "valid-event" in messages, (
        f"expected the in-window control event to become readable, got {messages!r}"
    )
    assert "future-event" not in messages, (
        f"the too-new event must never be persisted, got {messages!r}"
    )

    control_resp = logs.put_log_events(
        logGroupName=group_name,
        logStreamName=stream_name,
        logEvents=[{"timestamp": now_ms + 1, "message": "control-event"}],
    )
    assert control_resp.get("rejectedLogEventsInfo") is None, (
        f"expected a fully in-window batch to be accepted with no rejection report, got {control_resp!r}"
    )

    messages_after_control = _poll_until(
        lambda: _all_messages(logs, group_name, stream_name),
        lambda msgs: "control-event" in msgs,
        timeout_s=30.0,
        interval_s=1.5,
    )
    assert "control-event" in messages_after_control, (
        f"expected the follow-up control event to become readable, got {messages_after_control!r}"
    )
    assert "future-event" not in messages_after_control, (
        f"the too-new event must remain permanently unreadable, got {messages_after_control!r}"
    )


def _all_messages(logs, group_name: str, stream_name: str) -> list[str]:
    resp = logs.get_log_events(
        logGroupName=group_name, logStreamName=stream_name, startFromHead=True
    )
    return [e["message"] for e in resp.get("events", [])]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s; last value: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
