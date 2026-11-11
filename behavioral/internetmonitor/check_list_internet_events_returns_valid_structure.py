"""list-internet-events-returns-valid-structure."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "list-internet-events-returns-valid-structure"
GROUP = "events"
SERVICES = ["internetmonitor"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListInternetEvents (global, account-independent) returns well-formed InternetEvent records with the
    documented required fields, and honors the EventType filter (only AVAILABILITY events come back)."""
    im = ctx.client("internetmonitor")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=1)

    page = im.list_internet_events(
        StartTime=start, EndTime=end, EventType="AVAILABILITY", MaxResults=10
    )
    events = page["InternetEvents"]
    assert isinstance(events, list), f"InternetEvents must be a list, got {type(events)!r}"
    # Internet Monitor's global outages feed is continuously populated for every AWS
    # account, independent of any monitor the caller has configured. An empty page here
    # means the filter or the feed itself is broken, not that the internet had a quiet day.
    assert events, "ListInternetEvents returned no AVAILABILITY events in the last 24h"
    for event in events:
        assert event["EventType"] == "AVAILABILITY", (
            f"EventType filter leaked a non-AVAILABILITY event: {event['EventType']!r}"
        )
        assert event["EventStatus"] in ("ACTIVE", "RESOLVED"), (
            f"unexpected EventStatus: {event['EventStatus']!r}"
        )
        expected_arn = f"arn:aws:internetmonitor::{account_id}:internet-event/{event['EventId']}"
        assert event["EventArn"] == expected_arn, (
            f"EventArn {event['EventArn']!r} != expected {expected_arn!r}"
        )
        assert isinstance(event["StartedAt"], datetime), (
            f"StartedAt is not a timestamp: {event['StartedAt']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
