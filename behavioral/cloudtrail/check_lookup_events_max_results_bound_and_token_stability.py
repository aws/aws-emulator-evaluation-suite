"""lookup-events-max-results-bound-and-token-stability."""

from __future__ import annotations

import datetime

from behavioral_harness import tags

CHECK = "lookup-events-max-results-bound-and-token-stability"
GROUP = 'lookup-events'
SERVICES = ['cloudtrail']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """LookupEvents accepts an over-maximum MaxResults with a 200 and clamps the page to 50 events
    plus a NextToken; a minted NextToken replays the same page and successive pages never repeat
    an EventId.
    """
    ct = ctx.client("cloudtrail")
    now = datetime.datetime.now(datetime.timezone.utc)
    window = {"StartTime": now - datetime.timedelta(days=89), "EndTime": now}

    # MaxResults at the modelled maximum is accepted and honoured exactly.
    at_max = ct.lookup_events(MaxResults=50, **window)
    assert at_max["ResponseMetadata"]["HTTPStatusCode"] == 200, at_max["ResponseMetadata"]
    assert isinstance(at_max.get("Events"), list), at_max
    assert len(at_max["Events"]) <= 50, len(at_max["Events"])
    baseline = len(at_max["Events"])

    # The ceiling is enforced on the response: over-maximum MaxResults is accepted, not refused
    # with InvalidMaxResultsException, and clamped to 50 (botocore does not validate 'max').
    for over_max in (51, 52, 100, 1000, 1001):
        clamped = ct.lookup_events(MaxResults=over_max, **window)
        assert clamped["ResponseMetadata"]["HTTPStatusCode"] == 200, (
            f"MaxResults={over_max}: {clamped['ResponseMetadata']}"
        )
        assert len(clamped["Events"]) <= 50, (
            f"MaxResults={over_max} returned {len(clamped['Events'])} events; LookupEvents "
            f"clamps the page to the modelled maximum of 50 rather than honouring the request"
        )
        if baseline == 50:
            # With a full page of history the clamp is observable: exactly 50, not more or fewer.
            assert len(clamped["Events"]) == 50, (
                f"MaxResults={over_max} returned {len(clamped['Events'])} events but a full "
                f"page is 50; the clamp must not truncate below the maximum either"
            )
            assert clamped.get("NextToken"), (
                f"MaxResults={over_max} returned a full clamped page with no NextToken; the "
                f"remaining history is unreachable"
            )

    # MaxResults=0 is not asserted: botocore rejects it client-side, so it never reaches the wire.

    # Control case still works after the clamped calls.
    page_one = ct.lookup_events(MaxResults=1, **window)
    assert page_one["ResponseMetadata"]["HTTPStatusCode"] == 200, page_one["ResponseMetadata"]
    assert len(page_one["Events"]) <= 1, page_one["Events"]

    token = page_one.get("NextToken")
    if not token:
        # Fewer than two pages of history in the window; cursor semantics are not observable.
        return

    # A minted NextToken is a stable cursor: replaying it returns the same page.
    replay_a = ct.lookup_events(MaxResults=1, NextToken=token, **window)
    replay_b = ct.lookup_events(MaxResults=1, NextToken=token, **window)
    ids_a = [e["EventId"] for e in replay_a["Events"]]
    ids_b = [e["EventId"] for e in replay_b["Events"]]
    assert ids_a == ids_b, f"same NextToken returned different pages: {ids_a} vs {ids_b}"

    # And it is not the page it came from.
    first_ids = [e["EventId"] for e in page_one["Events"]]
    assert not (set(first_ids) & set(ids_a)), (
        f"page 2 repeats an EventId from page 1: {set(first_ids) & set(ids_a)}"
    )

    # Walk a bounded number of further pages; no EventId may appear twice, and the
    # walk must terminate by exhausting the token rather than cycling.
    seen = set(first_ids) | set(ids_a)
    cursor = replay_a.get("NextToken")
    for _ in range(5):
        if not cursor:
            break
        page = ct.lookup_events(MaxResults=1, NextToken=cursor, **window)
        for event in page["Events"]:
            assert event["EventId"] not in seen, (
                f"EventId {event['EventId']} returned on two different pages"
            )
            seen.add(event["EventId"])
        next_cursor = page.get("NextToken")
        assert next_cursor != cursor, "NextToken did not advance — the cursor is cycling"
        cursor = next_cursor


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
