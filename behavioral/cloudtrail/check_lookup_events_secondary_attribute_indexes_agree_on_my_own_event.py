"""lookup-events-secondary-attribute-indexes-agree-on-my-own-event."""

from __future__ import annotations

import datetime
import json
import time
import uuid

from behavioral_harness import tags

CHECK = "lookup-events-secondary-attribute-indexes-agree-on-my-own-event"
GROUP = "data-plane"
SERVICES = ["cloudtrail"]

# Marks a failure as a missing data plane rather than a connection error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_INDEX_BUDGET_S = 255.0  # CloudTrail indexes a new event in roughly 80-136 s
_POLL_INTERVAL_S = 2.0
_PAGE_CEILING = 40

# The envelope member each AttributeKey filters on, so filter correctness is asserted rather than
# merely membership.
_ATTRIBUTE_TO_ENVELOPE = {
    "AccessKeyId": "AccessKeyId",
    "Username": "Username",
    "EventSource": "EventSource",
    "EventName": "EventName",
}

# ===== helpers =====


def _lookup_all(ct, **kw):
    """Page LookupEvents to exhaustion (bounded)."""
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
    return out


def _by_attribute(ct, key, value, *, start, end):
    return _lookup_all(
        ct,
        StartTime=start,
        EndTime=end,
        MaxResults=50,
        LookupAttributes=[{"AttributeKey": key, "AttributeValue": value}],
    )


def _find(events, token):
    for ev in events:
        if token in ev.get("CloudTrailEvent", ""):
            return ev
    return None


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """LookupEvents' AccessKeyId, Username, EventSource and EventName indexes all return this run's
    own event and filter exactly, and lookups for never-existing values return an empty list.
    """
    ct = ctx.client("cloudtrail")

    token = ctx.unique_name("sim2realctattrmarker").lower()
    emitted_at = datetime.datetime.now(datetime.timezone.utc)
    t0 = time.monotonic()
    ct.describe_trails(trailNameList=[token])

    window_start = emitted_at - datetime.timedelta(minutes=2)
    envelope = None
    polls = 0
    scanned = 0
    while time.monotonic() - t0 < _INDEX_BUDGET_S:
        polls += 1
        window_end = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
        events = _by_attribute(
            ct, "EventName", "DescribeTrails", start=window_start, end=window_end
        )
        scanned = len(events)
        envelope = _find(events, token)
        if envelope is not None:
            break
        time.sleep(_POLL_INTERVAL_S)
    waited = time.monotonic() - t0

    assert envelope is not None, (
        f"{DATAPLANE_MARKER}: CloudTrail never indexed an API call this check itself made. A "
        f"DescribeTrails call carrying the unique token {token!r} was made at "
        f"{emitted_at.isoformat()}; {polls} polls over {waited:.0f}s scanned {scanned} "
        f"DescribeTrails events and none mentioned it. Real AWS indexed markers of this shape in "
        f"80-136s."
    )
    record = json.loads(envelope["CloudTrailEvent"])
    event_id = envelope["EventId"]
    assert record["requestParameters"] == {"trailNameList": [token]}, (
        f"the event located by this run's token carries requestParameters "
        f"{record.get('requestParameters')!r}, expected {{'trailNameList': [{token!r}]}} -- "
        f"everything below is about the wrong event otherwise"
    )

    # Filter values are read off the event's own envelope, never written into the check.
    for member in ("AccessKeyId", "Username", "EventSource", "EventName"):
        assert member in envelope, (
            f"the LookupEvents envelope for this run's own call has no {member!r} member, so it "
            f"cannot be used as the filter value for the {member} index. Members present: "
            f"{sorted(envelope)!r}"
        )
        assert envelope[member], (
            f"the envelope's {member} is {envelope[member]!r}; an empty value cannot address an "
            f"index"
        )

    # A CLOSED window, so all five queries below are asked about the same immutable interval and
    # differences between them can only come from the filter.
    query_end = datetime.datetime.now(datetime.timezone.utc)

    # --- The four indexes must all return this event, and each must filter exactly.
    for attribute, envelope_member in _ATTRIBUTE_TO_ENVELOPE.items():
        value = envelope[envelope_member]
        hits = _by_attribute(ct, attribute, value, start=window_start, end=query_end)
        ids = {ev["EventId"] for ev in hits}
        assert event_id in ids, (
            f"LookupEvents with AttributeKey={attribute!r} AttributeValue={value!r} -- the value "
            f"read from this very event's own envelope -- returned {len(hits)} event(s) and this "
            f"event ({event_id!r}) was not among them. The service's {attribute} index disagrees "
            f"with the record it indexes"
        )
        mismatched = [
            (ev["EventId"], ev.get(envelope_member))
            for ev in hits
            if ev.get(envelope_member) != value
        ]
        assert not mismatched, (
            f"LookupEvents with AttributeKey={attribute!r} AttributeValue={value!r} returned "
            f"{len(mismatched)} of {len(hits)} event(s) whose own {envelope_member} is something "
            f"else: {mismatched[:5]!r}. The attribute is an exact-match server-side filter, not "
            f"a hint -- a target that ignores it and returns its whole window lands here"
        )

    # --- Cross-index agreement: the AccessKeyId index and the Username index describe the same
    # caller, so within one closed window the AccessKeyId result set for THIS key must be a
    # subset of the Username result set for THIS user. One principal, one session.
    by_key = {
        ev["EventId"]
        for ev in _by_attribute(
            ct, "AccessKeyId", envelope["AccessKeyId"], start=window_start, end=query_end
        )
    }
    by_user = {
        ev["EventId"]
        for ev in _by_attribute(
            ct, "Username", envelope["Username"], start=window_start, end=query_end
        )
    }
    assert by_key <= by_user, (
        f"every event made with access key {envelope['AccessKeyId']!r} was made by user "
        f"{envelope['Username']!r}, so the AccessKeyId result set must be a subset of the "
        f"Username result set for the same closed window. "
        f"{len(by_key - by_user)} event(s) are in the first and not the second: "
        f"{sorted(by_key - by_user)[:5]!r}"
    )

    # --- Run-unique values name nothing that ever existed, so no waiting window is needed.
    never_key = "AKIA" + uuid.uuid4().hex[:16].upper()
    never_user = ctx.unique_name("sim2realctneveruser")
    never_resource = ctx.unique_name("sim2realctneverresource")
    for attribute, value, why in (
        ("AccessKeyId", never_key,
         "a well-formed AKIA key id generated in this process and never issued by IAM"),
        ("Username", never_user, "a run-unique user name that has never existed"),
        ("ResourceName", never_resource,
         "a run-unique resource name that has never been created"),
    ):
        hits = _by_attribute(ct, attribute, value, start=window_start, end=query_end)
        assert hits == [], (
            f"LookupEvents with AttributeKey={attribute!r} AttributeValue={value!r} ({why}) "
            f"returned {len(hits)} event(s): "
            f"{[(ev.get('EventId'), ev.get('EventName')) for ev in hits[:5]]!r}. Nothing in any "
            f"account has ever carried that value, so the only correct answer is an empty list. "
            f"A target that treats LookupAttributes as advisory and answers with its window "
            f"fails here, and it is the same defect that would make every positive lookup above "
            f"pass for the wrong reason"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
