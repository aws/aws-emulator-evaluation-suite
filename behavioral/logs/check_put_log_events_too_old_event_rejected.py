"""put-log-events-too-old-event-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-log-events-too-old-event-rejected"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A batch mixing an event older than 14 days with a current one reports tooOldLogEventEndIndex 1,
    and GetLogEvents returns only the current event.
    """
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-lg-")
    stream_name = ctx.unique_name("sim2real-behav-ls-")

    logs.create_log_group(logGroupName=group_name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))
    logs.create_log_stream(logGroupName=group_name, logStreamName=stream_name)

    now_ms = int(time.time() * 1000)
    # CloudWatch Logs rejects events older than 14 days as "too old":
    # https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutLogEvents.html
    too_old_ms = now_ms - (16 * 24 * 60 * 60 * 1000)
    too_old_message = "sim2real-too-old-event-should-be-rejected"
    valid_message = "sim2real-valid-current-event-should-be-accepted"

    # Batch must be in chronological order (index 0 = too-old, index 1 = valid).
    resp = logs.put_log_events(
        logGroupName=group_name,
        logStreamName=stream_name,
        logEvents=[
            {"timestamp": too_old_ms, "message": too_old_message},
            {"timestamp": now_ms, "message": valid_message},
        ],
    )

    rejected = resp.get("rejectedLogEventsInfo")
    assert rejected is not None, "expected rejectedLogEventsInfo for a too-old event"
    assert rejected.get("tooOldLogEventEndIndex") == 1, (
        f"expected tooOldLogEventEndIndex==1 (only index 0 rejected), got {rejected!r}"
    )

    # Effect absent: the too-old event never lands, ever, in the stream. Held
    # across a settle window so a target that asynchronously (and wrongly)
    # persists an event it already reported as rejected cannot slip past a
    # single-shot read.
    def _messages():
        resp = logs.get_log_events(
            logGroupName=group_name,
            logStreamName=stream_name,
            startFromHead=True,
        )
        return [e["message"] for e in resp.get("events", [])]

    # Positive control: the valid event in the very same batch IS accepted.
    _poll_until(
        _messages,
        lambda msgs: valid_message in msgs,
        timeout_s=30.0,
        description="the valid event becomes readable",
    )
    for _ in range(6):
        messages = _messages()
        assert too_old_message not in messages, (
            f"too-old event was persisted despite being reported as rejected: {messages!r}"
        )
        assert messages == [valid_message], (
            f"only the valid event may ever be persisted in this stream: {messages!r}"
        )
        time.sleep(2.0)


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
