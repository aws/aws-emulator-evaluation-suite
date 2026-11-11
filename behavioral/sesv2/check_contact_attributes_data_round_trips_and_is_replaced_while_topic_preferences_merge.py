"""contact-attributes-data-round-trips-and-is-replaced-while-topic-preferences-merge."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "contact-attributes-data-round-trips-and-is-replaced-while-topic-preferences-merge"
GROUP = "contacts-v2"
SERVICES = ["sesv2"]

_TOPIC_A = "weekly"
_TOPIC_B = "promos"
_TOPICS = [
    {"TopicName": _TOPIC_A, "DisplayName": "Weekly", "DefaultSubscriptionStatus": "OPT_IN"},
    {"TopicName": _TOPIC_B, "DisplayName": "Promos", "DefaultSubscriptionStatus": "OPT_OUT"},
]
#: Deliberately not a flat string map, so the round trip covers every JSON type.
_ORIGINAL_ATTRIBUTES = {
    "tier": "gold",
    "visits": 17,
    "beta": True,
    "referrer": None,
    "tags": ["a", "b"],
    "address": {"city": "Seattle", "zip": "98109"},
}
#: Shares NO keys with the original, so a merge and a replace produce provably different documents.
_REPLACEMENT_ATTRIBUTES = {"locale": "en-GB", "score": 3.5}
_MALFORMED_ATTRIBUTES = '{"tier": "gold"'
_MALFORMED_REFUSAL = (
    "BadRequestException",
    "Attributes must be valid JSON and it can contain up to 1000 characters.",
)


@tags("resource:account-singleton:sesv2-contact-list", "axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetContact returns AttributesData as the stored JSON document; one UpdateContact replaces
    AttributesData wholesale while merging TopicPreferences. Malformed JSON is refused, no effect.

    Reference: https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_UpdateContact.html
    """
    sesv2 = ctx.client("sesv2")
    list_name = _create_contact_list(ctx)
    address = _create_contact(ctx, list_name)

    # Compared after parsing: SES may re-serialise the JSON.
    stored = sesv2.get_contact(ContactListName=list_name, EmailAddress=address)
    assert "AttributesData" in stored, (
        f"GetContact({address}) reports no AttributesData at all, although CreateContact supplied "
        f"one: keys={sorted(stored)}"
    )
    parsed = _parse(stored["AttributesData"], "GetContact after CreateContact")
    assert parsed == _ORIGINAL_ATTRIBUTES, (
        f"AttributesData did not round-trip: GetContact({address}) returned {parsed!r}, expected the "
        f"document this run supplied {_ORIGINAL_ATTRIBUTES!r}"
    )
    original_prefs = _preferences(stored)
    assert original_prefs == {_TOPIC_A: "OPT_OUT"}, (
        f"CreateContact supplied exactly one explicit preference but GetContact reports "
        f"{original_prefs!r}, expected {{{_TOPIC_A!r}: 'OPT_OUT'}}"
    )

    # Malformed JSON is refused, and the stored document is untouched.
    update_err = _error(
        lambda: sesv2.update_contact(
            ContactListName=list_name,
            EmailAddress=address,
            AttributesData=_MALFORMED_ATTRIBUTES,
        )
    )
    assert update_err == _MALFORMED_REFUSAL, (
        f"UpdateContact with AttributesData={_MALFORMED_ATTRIBUTES!r}, which is not valid JSON, "
        f"returned {update_err!r}, expected {_MALFORMED_REFUSAL!r}"
    )
    unchanged = sesv2.get_contact(ContactListName=list_name, EmailAddress=address)
    assert _parse(unchanged["AttributesData"], "after the refused update") == _ORIGINAL_ATTRIBUTES, (
        f"the refused UpdateContact still changed the stored AttributesData: now "
        f"{unchanged['AttributesData']!r}, expected the unchanged {_ORIGINAL_ATTRIBUTES!r}"
    )

    # One call carries both payloads, which makes the replace-vs-merge asymmetry observable.
    sesv2.update_contact(
        ContactListName=list_name,
        EmailAddress=address,
        AttributesData=json.dumps(_REPLACEMENT_ATTRIBUTES),
        TopicPreferences=[{"TopicName": _TOPIC_B, "SubscriptionStatus": "OPT_IN"}],
    )
    after = sesv2.get_contact(ContactListName=list_name, EmailAddress=address)

    replaced = _parse(after["AttributesData"], "after the accepted update")
    assert replaced == _REPLACEMENT_ATTRIBUTES, (
        f"UpdateContact must REPLACE AttributesData, but GetContact returned {replaced!r}; expected "
        f"exactly {_REPLACEMENT_ATTRIBUTES!r} (the previous document was {_ORIGINAL_ATTRIBUTES!r}, so "
        f"any of its keys appearing here means the payloads were merged)"
    )

    merged = _preferences(after)
    assert merged == {_TOPIC_A: "OPT_OUT", _TOPIC_B: "OPT_IN"}, (
        f"UpdateContact must MERGE TopicPreferences, but GetContact reports {merged!r}; expected "
        f"both the pre-existing {_TOPIC_A}=OPT_OUT and the updated {_TOPIC_B}=OPT_IN. The very same "
        f"call replaced AttributesData, so a target applying one policy to both payloads fails here."
    )

    fresh = ctx.unique_name("sim2real-behav-attrs-bad-") + "@example.com"
    create_err = _error(
        lambda: sesv2.create_contact(
            ContactListName=list_name, EmailAddress=fresh, AttributesData=_MALFORMED_ATTRIBUTES
        )
    )
    assert create_err == _MALFORMED_REFUSAL, (
        f"CreateContact with AttributesData={_MALFORMED_ATTRIBUTES!r} returned {create_err!r}, "
        f"expected {_MALFORMED_REFUSAL!r}"
    )
    absent_err = _error(
        lambda: sesv2.get_contact(ContactListName=list_name, EmailAddress=fresh)
    )
    expected_absent = ("NotFoundException", f"{fresh} doesn't exist in List.")
    assert absent_err == expected_absent, (
        f"the refused CreateContact still created {fresh}: GetContact returned {absent_err!r}, "
        f"expected {expected_absent!r}"
    )


def _create_contact_list(ctx) -> str:
    """Create-or-adopt. SESv2 permits one contact list per account per region, so an existing list is
    adopted and its topic set restored on cleanup rather than deleted."""
    sesv2 = ctx.client("sesv2")
    existing = _sole_existing_list(sesv2)
    if existing is None:
        name = ctx.unique_name("sim2real-behav-attrsdata-")
        sesv2.create_contact_list(
            ContactListName=name,
            Topics=_TOPICS,
            Description="sim2real behavioral: AttributesData round trip and replace-vs-merge",
            Tags=[
                {"Key": "sim2real-managed", "Value": "true"},
                {"Key": "sim2real-check", "Value": CHECK},
            ],
        )
        ctx.on_cleanup(lambda: sesv2.delete_contact_list(ContactListName=name))
        return name

    original_topics = sesv2.get_contact_list(ContactListName=existing).get("Topics", [])
    ctx.on_cleanup(
        lambda: sesv2.update_contact_list(ContactListName=existing, Topics=original_topics)
    )
    sesv2.update_contact_list(ContactListName=existing, Topics=_TOPICS)
    return existing


def _sole_existing_list(sesv2) -> str | None:
    names = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        page = sesv2.list_contact_lists(**kwargs)
        names.extend(entry["ContactListName"] for entry in page.get("ContactLists", []))
        token = page.get("NextToken")
        if not token:
            break
    return names[0] if names else None


def _create_contact(ctx, list_name: str) -> str:
    sesv2 = ctx.client("sesv2")
    address = ctx.unique_name("sim2real-behav-attrs-") + "@example.com"
    sesv2.create_contact(
        ContactListName=list_name,
        EmailAddress=address,
        TopicPreferences=[{"TopicName": _TOPIC_A, "SubscriptionStatus": "OPT_OUT"}],
        AttributesData=json.dumps(_ORIGINAL_ATTRIBUTES),
    )
    ctx.on_cleanup(lambda: sesv2.delete_contact(ContactListName=list_name, EmailAddress=address))
    return address


def _parse(raw: str, phase: str):
    try:
        return json.loads(raw)
    except ValueError as err:
        raise AssertionError(
            f"{phase}: AttributesData came back as {raw!r}, which is not parseable JSON ({err}); "
            f"SES stores this field as a JSON document"
        ) from err


def _preferences(contact: dict) -> dict:
    """Explicit preferences only, as {topic: status}."""
    return {
        entry["TopicName"]: entry["SubscriptionStatus"]
        for entry in contact.get("TopicPreferences", [])
    }


def _error(fn) -> tuple:
    """Return the ClientError (code, message); raise on unexpected success."""
    try:
        fn()
    except ClientError as err:
        return (err.response["Error"]["Code"], err.response["Error"].get("Message"))
    raise AssertionError(
        "the call succeeded where a refusal was required; AttributesData that is not valid JSON "
        "must never be accepted"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
