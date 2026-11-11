"""describe-log-streams-order-by-last-event-time."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "describe-log-streams-order-by-last-event-time"
GROUP = "ordering"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DescribeLogStreams with orderBy=LastEventTime, descending=True returns streams
    sorted by most-recent-event first, in an order distinct from (and not incidentally
    equal to) plain ascending name ordering."""
    logs = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(
        logGroupName=group, tags={"sim2real": CHECK, "sim2real:managed": "true"}
    )
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))

    # Names sort ascending as a, b, c -- but we will ingest into them in the order
    # c, a, b so that LastEventTime-descending order is b, a, c: distinct from both
    # the name-ascending order (a, b, c) and the ingestion order (c, a, b).
    stream_a = ctx.unique_name("sim2real-behav-a-stream-")
    stream_b = ctx.unique_name("sim2real-behav-b-stream-")
    stream_c = ctx.unique_name("sim2real-behav-c-stream-")
    for s in (stream_a, stream_b, stream_c):
        logs.create_log_stream(logGroupName=group, logStreamName=s)

    def put(stream_name):
        logs.put_log_events(
            logGroupName=group,
            logStreamName=stream_name,
            logEvents=[{"timestamp": int(time.time() * 1000), "message": "tick"}],
        )

    def put_and_wait_registered(stream_name):
        put(stream_name)
        # Bounded poll: wait until this specific stream's lastEventTimestamp has
        # actually registered before moving on, instead of a bare fixed sleep.
        _wait_for_last_event_timestamp(ctx, group, stream_name, timeout_s=20.0)

    put_and_wait_registered(stream_c)
    put_and_wait_registered(stream_a)
    put_and_wait_registered(stream_b)

    ordered_names = _wait_for_last_event_order(ctx, group, [stream_a, stream_b, stream_c])

    name_ascending = sorted([stream_a, stream_b, stream_c])
    assert ordered_names != name_ascending, (
        "orderBy=LastEventTime produced the same order as plain name ordering; "
        "the two orderings should differ given the ingestion pattern used"
    )
    assert ordered_names == [stream_b, stream_a, stream_c], (
        f"expected LastEventTime-descending order [b, a, c], got {ordered_names}"
    )


def _wait_for_last_event_timestamp(ctx, group, stream_name, timeout_s=20.0):
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = logs.describe_log_streams(logGroupName=group, logStreamNamePrefix=stream_name)
        matches = [s for s in resp["logStreams"] if s["logStreamName"] == stream_name]
        if matches and matches[0].get("lastEventTimestamp") is not None:
            return matches[0]["lastEventTimestamp"]
        time.sleep(0.5)
    raise AssertionError(
        f"lastEventTimestamp never populated for stream {stream_name} within {timeout_s}s"
    )


def _wait_for_last_event_order(ctx, group, streams, timeout_s=30.0):
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    last_seen = None
    while time.monotonic() < deadline:
        resp = logs.describe_log_streams(
            logGroupName=group, orderBy="LastEventTime", descending=True
        )
        entries = [s for s in resp["logStreams"] if s["logStreamName"] in streams]
        last_seen = entries
        if len(entries) == len(streams) and all(
            e.get("lastEventTimestamp") is not None for e in entries
        ):
            return [e["logStreamName"] for e in entries]
        time.sleep(1.0)
    raise AssertionError(
        f"lastEventTimestamp never populated for all streams within {timeout_s}s: {last_seen}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
