"""put-log-events-message-exceeds-size-limit-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-log-events-message-exceeds-size-limit-rejected"
GROUP = "error-semantics"
SERVICES = ["logs"]

# A single log event message may be no larger than 1 MB (1,048,576 bytes) per
# https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutLogEvents.html
_MAX_EVENT_BYTES = 1_048_576


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutLogEvents rejects a single event whose message exceeds the 1 MB size limit and still
    accepts a normal-sized event afterward; once that event is readable, it is the stream's only one."""
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-plem-")
    stream_name = ctx.unique_name("stream-")

    logs.create_log_group(logGroupName=group_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))
    logs.create_log_stream(logGroupName=group_name, logStreamName=stream_name)

    now_ms = int(time.time() * 1000)
    oversized_message = "x" * (_MAX_EVENT_BYTES + 1)

    code, message = _error(
        lambda: logs.put_log_events(
            logGroupName=group_name,
            logStreamName=stream_name,
            logEvents=[{"timestamp": now_ms, "message": oversized_message}],
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    # An event's size is its UTF-8 message plus 26 bytes of per-event overhead.
    expected = f"Log event too large: {len(oversized_message) + 26} bytes exceeds limit of {_MAX_EVENT_BYTES}"
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # (b) positive control: a normal-sized event on the same stream still succeeds
    logs.put_log_events(
        logGroupName=group_name,
        logStreamName=stream_name,
        logEvents=[{"timestamp": now_ms, "message": "hello-world"}],
    )
    events = _poll_until(
        lambda: logs.get_log_events(
            logGroupName=group_name, logStreamName=stream_name, startFromHead=True
        )["events"],
        lambda evs: any(e["message"] == "hello-world" for e in evs),
        timeout_s=30.0,
        interval_s=1.0,
    )
    # (c) effect absent: ingestion is asynchronous, so the rejected event's absence is read from
    # the same stream read that first shows the control event.
    assert len(events) == 1 and events[0]["message"] == "hello-world", (
        f"expected exactly one event with message 'hello-world', got {events!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
