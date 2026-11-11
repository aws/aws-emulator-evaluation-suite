"""lookup-events-returns-the-record-for-my-own-api-call."""

from __future__ import annotations

import datetime
import json
import time

from behavioral_harness import tags

CHECK = "lookup-events-returns-the-record-for-my-own-api-call"
GROUP = 'data-plane'
SERVICES = ['cloudtrail']

# Marks the expiry failure as a target with no audit pipeline, not a slow environment: the
# expiry message carries a poll count and an elapsed time that read like slowness.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

# LookupEvents indexes a management event about 135 s after the call; the poll budget is about
# twice that.
_INDEX_BUDGET_S = 255.0
_POLL_INTERVAL_S = 2.0
_PAGE_CEILING = 40


def _lookup_all(ct, **kw):
    """Page LookupEvents to exhaustion (bounded), so membership is never judged from one page."""
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


def _parse_iso8601(value):
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c2")
def run(ctx) -> None:
    """After a DescribeTrails call carrying a unique token, LookupEvents returns that call's record within the
    index budget, with eventName, eventSource, requestParameters, awsRegion, recipientAccountId, caller ARN,
    readOnly, eventCategory, eventType and eventTime matching the call and its envelope agreeing."""
    ct = ctx.client("cloudtrail")

    # Emit the marker as the very first act so the index has maximum time to catch up.
    token = ctx.unique_name("sim2realctmarker").lower()
    emitted_at = datetime.datetime.now(datetime.timezone.utc)
    t0 = time.monotonic()
    ct.describe_trails(trailNameList=[token])

    ident = ctx.client("sts").get_caller_identity()
    account = ident["Account"]
    caller_arn = ident["Arn"]

    window_start = emitted_at - datetime.timedelta(minutes=2)
    record = None
    envelope = None
    polls = 0
    scanned = 0
    while time.monotonic() - t0 < _INDEX_BUDGET_S:
        polls += 1
        events = _lookup_all(
            ct,
            StartTime=window_start,
            EndTime=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),
            MaxResults=50,
            LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "DescribeTrails"}],
        )
        scanned = len(events)
        for ev in events:
            if token in ev.get("CloudTrailEvent", ""):
                envelope = ev
                record = json.loads(ev["CloudTrailEvent"])
                break
        if record is not None:
            break
        time.sleep(_POLL_INTERVAL_S)
    waited = time.monotonic() - t0

    assert record is not None, (
        f"{DATAPLANE_MARKER}: CloudTrail never produced an audit record for an API call this "
        f"check itself made. A DescribeTrails call carrying the unique token {token!r} was made "
        f"at {emitted_at.isoformat()}; {polls} LookupEvents polls over {waited:.0f}s scanned "
        f"{scanned} DescribeTrails events in the window and none of them mentioned it. Real AWS "
        f"indexed the same marker shape in 135s. A target that accepts LookupEvents but never "
        f"returns the caller's own calls is not auditing anything."
    )

    # The record describes THIS call, not merely some call.
    assert record["eventName"] == "DescribeTrails", (
        f"the record matching this run's token names the wrong operation: "
        f"eventName={record.get('eventName')!r}"
    )
    assert record["eventSource"] == "cloudtrail.amazonaws.com", (
        f"eventSource is {record.get('eventSource')!r}, expected cloudtrail.amazonaws.com"
    )
    assert record["requestParameters"] == {"trailNameList": [token]}, (
        f"requestParameters must reproduce the request verbatim; the call passed "
        f"trailNameList=[{token!r}] but the record carries {record.get('requestParameters')!r}. "
        f"A target that records the operation but discards its arguments fails here."
    )
    assert record["awsRegion"] == ctx.region, (
        f"awsRegion is {record.get('awsRegion')!r}, expected the region the call was made in "
        f"({ctx.region!r})"
    )
    assert record["recipientAccountId"] == account, (
        f"recipientAccountId is {record.get('recipientAccountId')!r}, expected the calling "
        f"account {account!r}"
    )
    assert record["userIdentity"]["arn"] == caller_arn, (
        f"userIdentity.arn is {record['userIdentity'].get('arn')!r}, expected the caller "
        f"{caller_arn!r} -- a target that fabricates a generic principal fails here, and "
        f"userIdentity is the single member every audit consumer keys on"
    )
    assert record["readOnly"] is True, (
        f"readOnly is {record.get('readOnly')!r} for DescribeTrails, which is a read-only "
        f"operation; the member is a JSON boolean in the payload, not a string"
    )
    assert record["eventCategory"] == "Management", (
        f"eventCategory is {record.get('eventCategory')!r}, expected Management"
    )
    assert record["eventType"] == "AwsApiCall", (
        f"eventType is {record.get('eventType')!r}, expected AwsApiCall"
    )

    # The envelope and the payload it wraps must agree. An emulator that synthesises the two
    # independently disagrees here even when each looks individually plausible.
    assert envelope["EventId"] == record["eventID"], (
        f"the LookupEvents envelope's EventId {envelope['EventId']!r} disagrees with the "
        f"embedded record's own eventID {record.get('eventID')!r}"
    )
    assert envelope["EventName"] == record["eventName"], (
        f"envelope EventName {envelope['EventName']!r} disagrees with payload eventName "
        f"{record['eventName']!r}"
    )
    assert envelope["ReadOnly"] == "true", (
        f"the envelope's ReadOnly member is stringly typed and must be exactly 'true' for a "
        f"read-only call; got {envelope.get('ReadOnly')!r} (payload readOnly is "
        f"{record['readOnly']!r})"
    )
    skew = abs((_parse_iso8601(record["eventTime"]) - envelope["EventTime"]).total_seconds())
    assert skew < 1.0, (
        f"envelope EventTime {envelope['EventTime']!r} and payload eventTime "
        f"{record['eventTime']!r} denote instants {skew}s apart"
    )
    # The recorded instant is the instant of the call, not the instant of indexing.
    lag = abs((_parse_iso8601(record["eventTime"]) - emitted_at).total_seconds())
    assert lag < 60.0, (
        f"the record's eventTime {record['eventTime']!r} is {lag:.0f}s from when the call was "
        f"actually made ({emitted_at.isoformat()}); a target that timestamps the record at "
        f"INDEXING time rather than at CALL time fails here, and every log-correlation "
        f"workflow depends on the difference"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
