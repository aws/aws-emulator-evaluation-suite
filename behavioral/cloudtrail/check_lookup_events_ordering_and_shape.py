"""lookup-events-ordering-and-shape."""

from __future__ import annotations

import datetime
import time

from behavioral_harness import tags


CHECK = "lookup-events-ordering-and-shape"
GROUP = 'lookup-events'
SERVICES = ['cloudtrail']

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _events_over(ct, days: int, limit: int):
    now = datetime.datetime.now(datetime.timezone.utc)
    resp = ct.lookup_events(
        StartTime=now - datetime.timedelta(days=days), EndTime=now, MaxResults=limit,
    )
    return resp["Events"]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """LookupEvents with MaxResults 5 returns 1-5 events newest-first, each with EventId, EventName,
    EventSource and CloudTrailEvent; an empty 90-day history fails, so an unimplemented lookup cannot pass."""
    ct = ctx.client("cloudtrail")

    # The check's own management calls are history a target that lists events at once returns
    # within the short poll; AWS lists them minutes later, so there the answer is the account's
    # earlier history, widened once to the full 90-day retention window.
    for _ in range(2):
        ct.describe_trails()
    deadline = time.monotonic() + _budget_s(ctx, 30.0)
    while True:
        events = _events_over(ct, days=7, limit=5)
        if events or time.monotonic() >= deadline:
            break
        time.sleep(1.0)
    if not events:
        events = _events_over(ct, days=89, limit=5)
    assert events, (
        f"{DATAPLANE_MARKER}: LookupEvents returned zero management events over the full 90-day "
        f"retention window for account {ctx.client('sts').get_caller_identity()['Account']}, "
        f"after this check's own DescribeTrails calls. CloudTrail's management-event history "
        f"needs no trail and is always on; a target returning no events is not auditing anything, and "
        f"the ordering/shape assertions below would otherwise pass vacuously on an empty list."
    )

    assert isinstance(events, list), f"Events is {type(events).__name__}, not a list: {events!r}"
    assert len(events) <= 5, f"MaxResults=5 but got {len(events)} events: {events}"

    times = [e["EventTime"] for e in events]
    assert times == sorted(times, reverse=True), (
        f"Events are not newest-first: EventTime sequence {times} is not descending"
    )

    for event in events:
        assert "EventId" in event, f"event missing EventId: {event}"
        assert "EventName" in event, f"event missing EventName: {event}"
        assert "EventSource" in event, f"event missing EventSource: {event}"
        assert "CloudTrailEvent" in event, f"event missing CloudTrailEvent: {event}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
