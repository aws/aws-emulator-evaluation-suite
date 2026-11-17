"""describe-log-streams-lasteventtime-limit-one-pages-newest-to-oldest."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-log-streams-lasteventtime-limit-one-pages-newest-to-oldest"
GROUP = "ordering"
SERVICES = ["logs"]


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _wait_for_full_order(logs, group, expected_order, *, timeout_s=60.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last_seen = None
    while time.monotonic() < deadline:
        resp = logs.describe_log_streams(
            logGroupName=group, orderBy="LastEventTime", descending=True
        )
        names = [s["logStreamName"] for s in resp["logStreams"]]
        last_seen = names
        if names == expected_order:
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"LastEventTime-descending order never settled to {expected_order!r} "
        f"within {timeout_s}s; last seen {last_seen!r}"
    )


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DescribeLogStreams with orderBy=LastEventTime, descending, limit=1 walks three
    streams one per page, newest first, with a nextToken on every page but the last.
    """
    logs = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-order-")
    logs.create_log_group(logGroupName=group)
    ctx.on_cleanup(_teardown(
        lambda: logs.delete_log_group(logGroupName=group), "ResourceNotFoundException"
    ))

    # Discriminators a/b/c sort ascending as a, b, c by name, but the events below are
    # timestamped so the newest-to-oldest order is b, a, c -- distinct from name order,
    # which proves the walk below is driven by LastEventTime, not by name.
    stream_oldest = ctx.unique_name("sim2real-behav-c-stream-")
    stream_middle = ctx.unique_name("sim2real-behav-a-stream-")
    stream_newest = ctx.unique_name("sim2real-behav-b-stream-")
    for s in (stream_oldest, stream_middle, stream_newest):
        logs.create_log_stream(logGroupName=group, logStreamName=s)

    now_ms = int(time.time() * 1000)
    for s, ts in (
        (stream_oldest, now_ms - 3000),
        (stream_middle, now_ms - 2000),
        (stream_newest, now_ms - 1000),
    ):
        logs.put_log_events(
            logGroupName=group,
            logStreamName=s,
            logEvents=[{"timestamp": ts, "message": f"event for {s}"}],
        )

    expected_order = [stream_newest, stream_middle, stream_oldest]
    _wait_for_full_order(logs, group, expected_order)

    page1 = logs.describe_log_streams(
        logGroupName=group, orderBy="LastEventTime", descending=True, limit=1
    )
    assert [s["logStreamName"] for s in page1["logStreams"]] == [stream_newest], (
        f"page 1 held {[s['logStreamName'] for s in page1['logStreams']]!r}, "
        f"expected only {stream_newest!r}"
    )
    assert page1.get("nextToken"), f"page 1 carried no nextToken: {page1.get('nextToken')!r}"

    page2 = logs.describe_log_streams(
        logGroupName=group, orderBy="LastEventTime", descending=True, limit=1,
        nextToken=page1["nextToken"],
    )
    assert [s["logStreamName"] for s in page2["logStreams"]] == [stream_middle], (
        f"page 2 held {[s['logStreamName'] for s in page2['logStreams']]!r}, "
        f"expected only {stream_middle!r}"
    )
    assert page2.get("nextToken"), f"page 2 carried no nextToken: {page2.get('nextToken')!r}"

    page3 = logs.describe_log_streams(
        logGroupName=group, orderBy="LastEventTime", descending=True, limit=1,
        nextToken=page2["nextToken"],
    )
    assert [s["logStreamName"] for s in page3["logStreams"]] == [stream_oldest], (
        f"page 3 held {[s['logStreamName'] for s in page3['logStreams']]!r}, "
        f"expected only {stream_oldest!r}"
    )
    assert page3.get("nextToken") is None, (
        f"page 3 (the last page) carried a nextToken: {page3.get('nextToken')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
