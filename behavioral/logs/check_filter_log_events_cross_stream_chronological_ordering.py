"""filter-log-events-cross-stream-chronological-ordering."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "filter-log-events-cross-stream-chronological-ordering"
GROUP = "ordering"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """FilterLogEvents over several streams of one log group returns their events merged in ascending
    timestamp order, independent of the order the streams were written in."""
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-logs-order-")
    stream_a = "stream-a"
    stream_b = "stream-b"

    logs.create_log_group(logGroupName=group_name, tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))
    logs.create_log_stream(logGroupName=group_name, logStreamName=stream_a)
    logs.create_log_stream(logGroupName=group_name, logStreamName=stream_b)

    base = int(time.time() * 1000) - 60_000  # anchor a minute in the past

    # Stream A holds the even-offset timestamps, stream B the odd-offset ones.
    events_a = [
        {"timestamp": base + 0, "message": "evt-A-0"},
        {"timestamp": base + 2000, "message": "evt-A-2"},
        {"timestamp": base + 4000, "message": "evt-A-4"},
    ]
    events_b = [
        {"timestamp": base + 1000, "message": "evt-B-1"},
        {"timestamp": base + 3000, "message": "evt-B-3"},
        {"timestamp": base + 5000, "message": "evt-B-5"},
    ]

    # Write stream B (the "later interleaved" timestamps) BEFORE stream A, so
    # write order deliberately disagrees with the final merged timestamp order.
    logs.put_log_events(logGroupName=group_name, logStreamName=stream_b, logEvents=events_b)
    logs.put_log_events(logGroupName=group_name, logStreamName=stream_a, logEvents=events_a)

    expected_order = ["evt-A-0", "evt-B-1", "evt-A-2", "evt-B-3", "evt-A-4", "evt-B-5"]

    messages = _poll_until(
        lambda: _filtered_messages(logs, group_name),
        lambda msgs: len(msgs) >= len(expected_order),
        timeout_s=30.0,
        interval_s=1.5,
    )

    assert messages == expected_order, f"expected {expected_order}, got {messages}"


def _filtered_messages(logs, group_name: str) -> list[str]:
    resp = logs.filter_log_events(logGroupName=group_name, startFromHead=True)
    return [e["message"] for e in resp["events"]]


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
