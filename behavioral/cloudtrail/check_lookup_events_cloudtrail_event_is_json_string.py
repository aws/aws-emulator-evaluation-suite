"""lookup-events-cloudtrail-event-is-json-string."""

from __future__ import annotations

import datetime
import json
import re

from behavioral_harness import tags

_EVENT_VERSION_RE = re.compile(r"^\d+\.\d+$")


def _events_over(ct, days: int, limit: int):
    """LookupEvents over the trailing `days`, capped at `limit` events."""
    now = datetime.datetime.now(datetime.timezone.utc)
    resp = ct.lookup_events(
        StartTime=now - datetime.timedelta(days=days),
        EndTime=now,
        MaxResults=limit,
    )
    return resp


CHECK = "lookup-events-cloudtrail-event-is-json-string"
GROUP = 'lookup-events'
SERVICES = ['cloudtrail']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Every LookupEvents event carries CloudTrailEvent as a JSON string whose eventID, eventName, eventSource
    and eventTime match the envelope, and the envelope's ReadOnly is the string "true" or "false"; log consumers
    json.loads that field, so a nested object breaks them."""
    ct = ctx.client("cloudtrail")

    resp = _events_over(ct, days=1, limit=10)
    events = resp["Events"]
    if not events:
        # Widen once to the full 90-day LookupEvents retention window before giving up.
        resp = _events_over(ct, days=89, limit=10)
        events = resp["Events"]
    if not events:
        raise AssertionError(
            "account has no CloudTrail management-event history in the 90-day "
            "LookupEvents retention window, so the Event shape cannot be asserted "
            "without fabricating data"
        )

    assert isinstance(events, list), resp
    account = ctx.client("sts").get_caller_identity()["Account"]

    for event in events:
        raw = event.get("CloudTrailEvent")
        # THE assertion: a JSON string, not a nested object.
        assert isinstance(raw, str), f"CloudTrailEvent is {type(raw).__name__}, not str: {raw!r}"
        parsed = json.loads(raw)
        assert isinstance(parsed, dict), f"CloudTrailEvent did not parse to an object: {parsed!r}"

        # The wrapped record and its envelope must describe the same event.
        assert parsed["eventID"] == event["EventId"], (parsed["eventID"], event["EventId"])
        assert parsed["eventName"] == event["EventName"], (
            parsed["eventName"],
            event["EventName"],
        )
        assert parsed["eventSource"] == event["EventSource"], (
            parsed["eventSource"],
            event["EventSource"],
        )

        # Record-level fields every CloudTrail event carries.
        assert _EVENT_VERSION_RE.match(parsed["eventVersion"]), parsed["eventVersion"]
        assert isinstance(parsed["userIdentity"], dict), parsed["userIdentity"]
        assert parsed["awsRegion"], parsed.get("awsRegion")
        assert parsed["recipientAccountId"] == account, (
            parsed.get("recipientAccountId"),
            account,
        )

        # eventTime is an ISO-8601 Z instant in the record and a datetime in the
        # envelope; they must denote the same second.
        record_time = datetime.datetime.strptime(
            parsed["eventTime"], "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=datetime.timezone.utc)
        envelope_time = event["EventTime"]
        assert abs((record_time - envelope_time).total_seconds()) < 1.0, (
            parsed["eventTime"],
            envelope_time,
        )

        # Envelope ReadOnly is modelled as String, and must agree with the record.
        if "ReadOnly" in event:
            assert isinstance(event["ReadOnly"], str), (
                f"Event.ReadOnly is {type(event['ReadOnly']).__name__}, "
                f"not str: {event['ReadOnly']!r}"
            )
            assert event["ReadOnly"] in ("true", "false"), event["ReadOnly"]
            if "readOnly" in parsed:
                assert event["ReadOnly"] == str(parsed["readOnly"]).lower(), (
                    event["ReadOnly"],
                    parsed["readOnly"],
                )

        # Resources, when present, is a list of {ResourceType, ResourceName} entries.
        for resource in event.get("Resources", []):
            assert isinstance(resource, dict), resource
            assert set(resource) <= {"ResourceType", "ResourceName"}, resource

    # NextToken is present only when the page was filled.
    if len(events) < 10:
        assert "NextToken" not in resp, resp.get("NextToken")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
