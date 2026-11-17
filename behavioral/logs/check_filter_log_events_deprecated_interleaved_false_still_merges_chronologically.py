"""filter-log-events-deprecated-interleaved-false-still-merges-chronologically."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "filter-log-events-deprecated-interleaved-false-still-merges-chronologically"
GROUP = "ordering"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """FilterLogEvents ignores the deprecated interleaved=False request and still merges events
    from several streams by ascending timestamp rather than draining one stream before the next.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_FilterLogEvents.html
    """
    logs = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-interleaved-")
    stream_a = "stream-a"
    stream_b = "stream-b"

    logs.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    logs.create_log_stream(logGroupName=group, logStreamName=stream_a)
    logs.create_log_stream(logGroupName=group, logStreamName=stream_b)

    base = int(time.time() * 1000) - 60_000

    # Stream A holds every event written AFTER stream B's: if FilterLogEvents actually
    # honoured interleaved=False by draining one stream before the other, the response
    # would list stream B's three events before any of stream A's -- the write order --
    # rather than the merged ascending-timestamp order asserted below.
    events_b = [
        {"timestamp": base + 0, "message": "deprecated-evt-B-0"},
        {"timestamp": base + 2000, "message": "deprecated-evt-B-2"},
        {"timestamp": base + 4000, "message": "deprecated-evt-B-4"},
    ]
    events_a = [
        {"timestamp": base + 1000, "message": "deprecated-evt-A-1"},
        {"timestamp": base + 3000, "message": "deprecated-evt-A-3"},
        {"timestamp": base + 5000, "message": "deprecated-evt-A-5"},
    ]
    logs.put_log_events(logGroupName=group, logStreamName=stream_a, logEvents=events_a)
    logs.put_log_events(logGroupName=group, logStreamName=stream_b, logEvents=events_b)

    expected_order = [
        "deprecated-evt-B-0",
        "deprecated-evt-A-1",
        "deprecated-evt-B-2",
        "deprecated-evt-A-3",
        "deprecated-evt-B-4",
        "deprecated-evt-A-5",
    ]

    messages = _poll_until(
        lambda: _filtered_messages(logs, group),
        lambda msgs: len(msgs) >= len(expected_order),
        timeout_s=30.0,
        interval_s=1.5,
    )
    assert messages == expected_order, (
        f"interleaved=False must still be ignored and the response merged by ascending "
        f"timestamp; expected {expected_order!r}, got {messages!r}"
    )


def _filtered_messages(logs, group: str) -> list[str]:
    resp = logs.filter_log_events(logGroupName=group, startFromHead=True, interleaved=False)
    return [e["message"] for e in resp["events"]]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s; last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
