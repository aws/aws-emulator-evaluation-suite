"""lookup-events-single-lookup-attribute-enforced."""

from __future__ import annotations

import datetime

from behavioral_harness import tags
from botocore.exceptions import ClientError

# This check provisions nothing: it reads only AWS-maintained history.


def _error_response(fn):
    """Call fn(); return the full botocore error response dict, or None if it succeeded."""
    try:
        fn()
    except ClientError as exc:
        return exc.response
    return None


CHECK = "lookup-events-single-lookup-attribute-enforced"
GROUP = 'overly-permissive'
SERVICES = ['cloudtrail']


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """LookupEvents applies only the FIRST of several LookupAttributes (checked in both orders),
    while an unknown AttributeKey or an out-of-domain value is refused with
    InvalidLookupAttributesException: a filter that ANDs or ignores attributes misleads an audit."""
    ct = ctx.client("cloudtrail")

    now = datetime.datetime.now(datetime.timezone.utc)
    window = {"StartTime": now - datetime.timedelta(days=89), "EndTime": now}

    # A value no event can carry: unique per run, so "no match" is a fact, not a guess.
    impossible = {"AttributeKey": "EventName", "AttributeValue": ctx.unique_name("NoSuchEventName")}

    def lookup(attributes, **extra):
        return ct.lookup_events(LookupAttributes=attributes, MaxResults=5, **window, **extra)

    # Discover a broad attribute from real history rather than hardcoding one, so the
    # precedence assertions below cannot be vacuously satisfied by an empty result set.
    unfiltered = ct.lookup_events(MaxResults=5, **window)
    assert unfiltered["ResponseMetadata"]["HTTPStatusCode"] == 200, unfiltered["ResponseMetadata"]
    assert isinstance(unfiltered.get("Events"), list), unfiltered

    if unfiltered["Events"]:
        source = unfiltered["Events"][0]["EventSource"]
        broad = {"AttributeKey": "EventSource", "AttributeValue": source}

        # Positive control: ONE valid LookupAttribute is accepted AND actually filters.
        ok = lookup([broad])
        assert ok["ResponseMetadata"]["HTTPStatusCode"] == 200, ok["ResponseMetadata"]
        assert ok["Events"], f"EventSource={source} was just observed but matched nothing"
        assert all(e["EventSource"] == source for e in ok["Events"]), (
            f"a single EventSource={source} attribute did not filter: "
            f"{sorted({e['EventSource'] for e in ok['Events']})}"
        )

        # Direction one: the broad attribute FIRST, an impossible one second. The impossible
        # attribute is ignored, so the result is the broad result. An emulator that
        # intersects the attributes returns nothing here and fails.
        first_wins = lookup([broad, impossible])
        assert first_wins["ResponseMetadata"]["HTTPStatusCode"] == 200, first_wins["ResponseMetadata"]
        assert first_wins["Events"], (
            "a second LookupAttribute that matches nothing emptied the result; real AWS "
            "ignores every attribute after the first, it does not intersect them"
        )
        assert all(e["EventSource"] == source for e in first_wins["Events"]), (
            f"the FIRST attribute stopped filtering once a second was added: "
            f"{sorted({e['EventSource'] for e in first_wins['Events']})}"
        )

        # Direction two: the impossible attribute FIRST. Now it is the one that applies, so
        # the result must be empty. An emulator that ignores the list entirely, or that
        # unions the attributes, returns events here and fails.
        first_loses = lookup([impossible, broad])
        assert first_loses["ResponseMetadata"]["HTTPStatusCode"] == 200, first_loses["ResponseMetadata"]
        assert first_loses["Events"] == [], (
            f"the FIRST LookupAttribute was not applied: an EventName that cannot exist "
            f"still returned {len(first_loses['Events'])} events, so the list is being "
            f"ignored or unioned rather than reduced to its first element"
        )

        # A third element changes nothing: still exactly the first attribute.
        three = lookup([impossible, broad, {"AttributeKey": "ReadOnly", "AttributeValue": "true"}])
        assert three["Events"] == [], three["Events"]
    else:
        # No management events in the 89-day window, so no attribute is observably broad and
        # the precedence property is not measurable. The refusals below still run.
        source = None

    # Break exactly one thing: an AttributeKey outside the modelled enum (EventId | EventName
    # | ReadOnly | Username | ResourceType | ResourceName | EventSource | AccessKeyId). An
    # emulator must not treat an unknown key as "no filter" — that is over-permissive.
    unknown = _error_response(
        lambda: lookup([{"AttributeKey": "NotARealAttributeKey", "AttributeValue": "anything"}])
    )
    assert unknown is not None, "LookupEvents accepted an AttributeKey outside the enum"
    assert unknown["Error"]["Code"] == "InvalidLookupAttributesException", unknown["Error"]
    assert unknown["Error"].get("Message") == "Lookup attribute key cannot be null or empty.", unknown["Error"]
    assert unknown["ResponseMetadata"]["HTTPStatusCode"] == 400, unknown["ResponseMetadata"]
    # Effect absent: the refusal must not carry a partial result page.
    assert "Events" not in unknown, unknown.get("Events")
    assert "NextToken" not in unknown, unknown.get("NextToken")

    # Break a different single thing: a MODELLED key given a value outside that key's own
    # domain. ReadOnly is documented as "true" | "false"; anything else is refused, not
    # silently treated as an unfiltered scan of the account's whole audit history.
    bad_value = _error_response(
        lambda: lookup([{"AttributeKey": "ReadOnly", "AttributeValue": "maybe"}])
    )
    assert bad_value is not None, "LookupEvents accepted ReadOnly=maybe"
    assert bad_value["Error"]["Code"] == "InvalidLookupAttributesException", bad_value["Error"]
    assert bad_value["Error"].get("Message") == "Lookup attribute key is invalid.", bad_value["Error"]
    assert "Events" not in bad_value, bad_value.get("Events")

    # And ReadOnly's real domain IS accepted, so the refusal above was about the value.
    for legal in ("true", "false"):
        page = lookup([{"AttributeKey": "ReadOnly", "AttributeValue": legal}])
        assert page["ResponseMetadata"]["HTTPStatusCode"] == 200, (legal, page["ResponseMetadata"])
        assert isinstance(page.get("Events"), list), (legal, page)

    # A valid key with a meaningless (whitespace) AttributeValue is accepted and matches
    # NOTHING — it is a real filter, not an unfiltered scan.
    blank = lookup([{"AttributeKey": "EventName", "AttributeValue": " "}])
    assert blank["ResponseMetadata"]["HTTPStatusCode"] == 200, blank["ResponseMetadata"]
    assert blank["Events"] == [], (
        f"EventName=' ' returned {len(blank['Events'])} events; a whitespace value must "
        f"match nothing, not fall through to an unfiltered scan"
    )

    # Final control: the surface is still usable after all three refusals.
    if source is not None:
        final = lookup([{"AttributeKey": "EventSource", "AttributeValue": source}])
        assert final["ResponseMetadata"]["HTTPStatusCode"] == 200, final["ResponseMetadata"]
        assert all(e["EventSource"] == source for e in final["Events"]), final["Events"]
    else:
        final = ct.lookup_events(MaxResults=5, **window)
        assert final["ResponseMetadata"]["HTTPStatusCode"] == 200, final["ResponseMetadata"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
