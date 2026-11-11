"""lookup-events-window-boundary-is-exact-and-future-window-is-empty."""

from __future__ import annotations

import datetime
import time

from behavioral_harness import tags

CHECK = "lookup-events-window-boundary-is-exact-and-future-window-is-empty"
GROUP = 'data-plane'
SERVICES = ['cloudtrail']

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_PAGE_CEILING = 60
#: Own management calls, spaced so that their events have distinct EventTimes on either side of a
#: one-second shift.
_OWN_EVENTS = 5
_OWN_EVENT_SPACING_S = 1.2
#: Real-AWS wall bound for the own events to reach event history, which CloudTrail delivers
#: minutes after the call.
_DEADLINE_S = 780.0
_POLL_S = 5.0
_OWN = [{"AttributeKey": "EventName", "AttributeValue": "DescribeTrails"}]


def _lookup_all(ct, **kw):
    """Page LookupEvents to exhaustion (bounded). A pivot can be on any page, so presence is
    never decided from page one."""
    out = []
    nxt = None
    for _ in range(_PAGE_CEILING):
        if nxt:
            kw["NextToken"] = nxt
        else:
            kw.pop("NextToken", None)
        resp = ct.lookup_events(**kw)
        out.extend(resp["Events"])
        nxt = resp.get("NextToken")
        if not nxt:
            return out
    raise AssertionError(
        f"LookupEvents did not terminate within {_PAGE_CEILING} pages for {kw!r}; the window is "
        f"too busy to compare sets over and the comparison would be made against truncated data"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c2")
def run(ctx) -> None:
    """LookupEvents windows are inclusive at both ends: [T, T] returns the event at T, while windows starting one
    second after or ending one second before T exclude it (each non-empty); a window wholly in the future,
    one hour or thirty days out, returns exactly no events and no NextToken, not the most recent events."""
    ct = ctx.client("cloudtrail")
    # The check's own spaced DescribeTrails calls are the records the boundaries are probed on:
    # every window below is filtered to that event name and starts before the first call. Event
    # history lists a call minutes after it is made, so the check polls until all are listed.
    start = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0) - datetime.timedelta(seconds=2)
    for i in range(_OWN_EVENTS):
        if i:
            time.sleep(_OWN_EVENT_SPACING_S)
        ct.describe_trails()

    deadline = time.monotonic() + _budget_s(ctx, _DEADLINE_S)
    while True:
        end = datetime.datetime.now(datetime.timezone.utc)
        events = _lookup_all(ct, LookupAttributes=_OWN, StartTime=start, EndTime=end, MaxResults=50)
        if len(events) >= _OWN_EVENTS or time.monotonic() >= deadline:
            break
        time.sleep(_POLL_S)
    assert len(events) >= _OWN_EVENTS, (
        f"{DATAPLANE_MARKER}: LookupEvents listed {len(events)} DescribeTrails events in "
        f"[{start.isoformat()}, {end.isoformat()}] after this check's own {_OWN_EVENTS} "
        f"DescribeTrails calls in that window. A boundary cannot be probed without records to "
        f"place either side of it. An audit service with no retrievable history is not auditing."
    )

    # Choose the pivot that leaves the most records on BOTH sides of its one-second shifts, so
    # that neither exclusion leg can pass vacuously. Selecting the newest or oldest event would
    # leave one shifted window empty and prove nothing about that bound.
    def _sides(candidate):
        t = candidate["EventTime"]
        before = sum(1 for e in events if e["EventTime"] <= t - datetime.timedelta(seconds=1))
        after = sum(1 for e in events if e["EventTime"] >= t + datetime.timedelta(seconds=1))
        return before, after

    pivot = max(events, key=lambda e: min(_sides(e)))
    n_before, n_after = _sides(pivot)
    pivot_id = pivot["EventId"]
    pt = pivot["EventTime"]
    assert n_before >= 1 and n_after >= 1, (
        f"no event in the window has records both at least a second before and at least a "
        f"second after it (best pivot {pivot_id!r} at {pt!r} has {n_before} before / {n_after} "
        f"after, over {len(events)} events). Both exclusion legs would be vacuous, so the "
        f"boundary is not measurable on this history rather than satisfied by it."
    )

    at_boundary = {e["EventId"] for e in _lookup_all(
        ct, LookupAttributes=_OWN, StartTime=pt, EndTime=pt, MaxResults=50)}
    assert pivot_id in at_boundary, (
        f"a window of exactly [EventTime, EventTime] did not return the event at that instant: "
        f"pivot {pivot_id!r} ({pivot['EventName']}) at {pt!r} is absent from a "
        f"{len(at_boundary)}-event result. Both bounds are inclusive on real AWS."
    )

    from_pivot = {e["EventId"] for e in _lookup_all(
        ct, LookupAttributes=_OWN, StartTime=pt, EndTime=end, MaxResults=50)}
    assert pivot_id in from_pivot, (
        f"the pivot {pivot_id!r} is excluded by a window whose StartTime is exactly its own "
        f"EventTime {pt!r}, so the lower bound is exclusive; real AWS includes it"
    )

    after_ids = {e["EventId"] for e in _lookup_all(
        ct, LookupAttributes=_OWN, StartTime=pt + datetime.timedelta(seconds=1), EndTime=end, MaxResults=50)}
    assert len(after_ids) >= 1, (
        f"the window [EventTime+1s, {end.isoformat()}] came back empty although {n_after} "
        f"events in the polled window are at or after that instant; the exclusion below "
        f"would be vacuous"
    )
    assert pivot_id not in after_ids, (
        f"the pivot {pivot_id!r} at {pt!r} is still returned by a window starting one second "
        f"AFTER its own EventTime, so the lower bound is not exact ({len(after_ids)} events "
        f"returned)"
    )

    to_pivot = {e["EventId"] for e in _lookup_all(
        ct, LookupAttributes=_OWN, StartTime=start, EndTime=pt, MaxResults=50)}
    assert pivot_id in to_pivot, (
        f"the pivot {pivot_id!r} is excluded by a window whose EndTime is exactly its own "
        f"EventTime {pt!r}, so the upper bound is exclusive; real AWS includes it"
    )

    before_ids = {e["EventId"] for e in _lookup_all(
        ct, LookupAttributes=_OWN, StartTime=start, EndTime=pt - datetime.timedelta(seconds=1), MaxResults=50)}
    assert len(before_ids) >= 1, (
        f"the window [{start.isoformat()}, EventTime-1s] came back empty although {n_before} "
        f"events in the polled window are at or before that instant; the exclusion below "
        f"would be vacuous"
    )
    assert pivot_id not in before_ids, (
        f"the pivot {pivot_id!r} at {pt!r} is still returned by a window ending one second "
        f"BEFORE its own EventTime, so the upper bound is not exact ({len(before_ids)} events "
        f"returned)"
    )

    # A valid but unsatisfiable window is an exactly-empty 200, not a fallback to recent events.
    now = datetime.datetime.now(datetime.timezone.utc)
    future = ct.lookup_events(StartTime=now + datetime.timedelta(hours=1),
                              EndTime=now + datetime.timedelta(hours=2), MaxResults=50)
    assert future["Events"] == [], (
        f"a window entirely in the future returned {len(future['Events'])} events; the first is "
        f"{future['Events'][0].get('EventName')!r} at {future['Events'][0].get('EventTime')!r} "
        f"-- the service ignored the window and fell back to recent events"
    )
    assert "NextToken" not in future, (
        f"an empty result must carry no NextToken; got {future.get('NextToken')!r}, which makes "
        f"a paginating consumer loop forever over nothing"
    )
    assert future["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"an unsatisfiable-but-VALID window is not an error: expected HTTP 200, got "
        f"{future['ResponseMetadata']['HTTPStatusCode']!r}"
    )

    far_future = ct.lookup_events(StartTime=now + datetime.timedelta(days=30),
                                  EndTime=now + datetime.timedelta(days=31), MaxResults=50)
    assert far_future["Events"] == [], (
        f"a window 30 days in the future returned {len(far_future['Events'])} events, so the "
        f"near-future emptiness above was a boundary artefact rather than the window being "
        f"honoured"
    )
    assert "NextToken" not in far_future, (
        f"the far-future empty result carries NextToken={far_future.get('NextToken')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
