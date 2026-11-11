"""get-log-events-pagination-token-exactness."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-log-events-pagination-token-exactness"
GROUP = 'log-events'
SERVICES = ['logs']


# ===== helpers =====
def _now_ms() -> int:
    return int(time.time() * 1000)


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


# ===== end helpers =====


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetLogEvents' cursor is exact: forward paging honours ``limit`` and walks each event once, the
    cursor past the end reaches a fixed point (``events: []`` and the same token echoed back), and
    startFromHead=False reads the tail in ascending timestamp order.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-pagetokens-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)

    base = _now_ms()
    expected = [f"page-event-{i}" for i in range(5)]
    svc.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": base + i * 1000, "message": m} for i, m in enumerate(expected)],
    )

    _poll_until(
        lambda: [
            e["message"]
            for e in svc.get_log_events(
                logGroupName=group, logStreamName=stream, startFromHead=True
            ).get("events", [])
        ],
        lambda msgs: msgs == expected,
        timeout_s=60,
        interval_s=2.0,
        description="all 5 events readable in order",
    )

    # --- 1. Forward paging with limit=2 walks 2 + 2 + 1 with no repeats.
    page1 = svc.get_log_events(
        logGroupName=group, logStreamName=stream, startFromHead=True, limit=2
    )
    assert [e["message"] for e in page1["events"]] == expected[0:2], page1["events"]
    assert page1.get("nextForwardToken"), f"page 1 must carry a nextForwardToken: {page1!r}"
    assert page1.get("nextBackwardToken"), f"page 1 must carry a nextBackwardToken: {page1!r}"

    page2 = svc.get_log_events(
        logGroupName=group,
        logStreamName=stream,
        startFromHead=True,
        limit=2,
        nextToken=page1["nextForwardToken"],
    )
    assert [e["message"] for e in page2["events"]] == expected[2:4], page2["events"]

    page3 = svc.get_log_events(
        logGroupName=group,
        logStreamName=stream,
        startFromHead=True,
        limit=2,
        nextToken=page2["nextForwardToken"],
    )
    assert [e["message"] for e in page3["events"]] == expected[4:5], page3["events"]

    walked = (
        [e["message"] for e in page1["events"]]
        + [e["message"] for e in page2["events"]]
        + [e["message"] for e in page3["events"]]
    )
    assert walked == expected, f"forward paging repeated or skipped events: {walked!r}"

    # --- 2. Exhausted cursor: empty page, and the forward token reaches a fixed
    # point. Real AWS does NOT echo back the token from the last non-empty page:
    # the first call past the end returns events=[] with a token normalised to the
    # true end-of-stream position (measured: page3's token
    # f/...656690180 came back as f/...964365311). Every call after that echoes
    # its own input token back unchanged, which is the property a polling loop
    # needs.
    exhausted_token = page3["nextForwardToken"]
    page4 = svc.get_log_events(
        logGroupName=group,
        logStreamName=stream,
        startFromHead=True,
        limit=2,
        nextToken=exhausted_token,
    )
    assert page4.get("events", []) == [], (
        f"paging past the end of the stream must return events=[], got {page4.get('events')!r}"
    )
    assert page4.get("nextForwardToken"), (
        f"an empty end-of-stream page must still carry a nextForwardToken: {page4!r}"
    )
    page5 = svc.get_log_events(
        logGroupName=group,
        logStreamName=stream,
        startFromHead=True,
        limit=2,
        nextToken=page4["nextForwardToken"],
    )
    assert page5.get("events", []) == [], (
        f"re-polling an end-of-stream token must return events=[], got {page5.get('events')!r}"
    )
    assert page5.get("nextForwardToken") == page4["nextForwardToken"], (
        "once the forward cursor is at the end of the stream GetLogEvents must echo back the "
        f"token it was given; passed {page4['nextForwardToken']!r}, got "
        f"{page5.get('nextForwardToken')!r}"
    )

    # --- 3. Backward from the head: nothing precedes event 0.
    backward = svc.get_log_events(
        logGroupName=group,
        logStreamName=stream,
        startFromHead=True,
        nextToken=page1["nextBackwardToken"],
    )
    assert backward.get("events", []) == [], (
        "paging backward from the first page must return events=[], got "
        f"{[e['message'] for e in backward.get('events', [])]!r}"
    )

    # --- 4. startFromHead=False reads the TAIL, ascending within the page.
    tail = svc.get_log_events(
        logGroupName=group, logStreamName=stream, startFromHead=False, limit=2
    )
    tail_msgs = [e["message"] for e in tail["events"]]
    assert tail_msgs == expected[-2:], (
        "startFromHead=False with limit=2 must return the two most recent events in "
        f"ascending order, got {tail_msgs!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
