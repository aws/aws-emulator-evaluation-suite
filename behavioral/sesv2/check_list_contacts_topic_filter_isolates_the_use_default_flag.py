"""list-contacts-topic-filter-isolates-the-use-default-flag."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-contacts-topic-filter-isolates-the-use-default-flag"
GROUP = "contact-list"
SERVICES = ["sesv2"]

# Two topics with opposite defaults, so the flag's effect cannot be mimicked by hardcoding one
# polarity.
_NEWS = "news"
_ALERTS = "alerts"
_TOPICS = [
    {"TopicName": _NEWS, "DisplayName": "News", "DefaultSubscriptionStatus": "OPT_OUT"},
    {"TopicName": _ALERTS, "DisplayName": "Alerts", "DefaultSubscriptionStatus": "OPT_IN"},
]
# CreateContact's visibility in ListContacts is a separate read path, so contacts are awaited.
_SETTLE_DEADLINE_S = 60.0
_SETTLE_INTERVAL_S = 2.0
_FREEZE_READS = 3


@tags("resource:account-singleton:sesv2-contact-list", "axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """With FilteredStatus fixed, flipping UseDefaultIfPreferenceUnavailable adds exactly the
    contacts with no preference for the topic, bucketed by that topic's DefaultSubscriptionStatus,
    while contacts with an explicit preference do not move.
    """
    sesv2 = ctx.client("sesv2")
    list_name = _create_contact_list(ctx)

    explicit_in = _create_contact(ctx, list_name, "optin-", [(_NEWS, "OPT_IN")])
    explicit_out = _create_contact(ctx, list_name, "optout-", [(_NEWS, "OPT_OUT")])
    silent = _create_contact(ctx, list_name, "silent-", [])
    everyone = {explicit_in, explicit_out, silent}

    settled = _await_all_visible(sesv2, list_name, everyone)
    assert settled == everyone, (
        f"unfiltered ListContacts returned {sorted(settled)}, expected exactly the three contacts "
        f"this check created {sorted(everyone)}"
    )

    # `news` default is OPT_OUT. The silent contact must appear in the OPT_OUT bucket only when the
    # flag is on, and never in the OPT_IN bucket.
    _assert_projection(sesv2, list_name, _NEWS, "OPT_OUT", False, {explicit_out}, "A")
    _assert_projection(sesv2, list_name, _NEWS, "OPT_OUT", True, {explicit_out, silent}, "B")
    _assert_projection(sesv2, list_name, _NEWS, "OPT_IN", False, {explicit_in}, "C")
    _assert_projection(sesv2, list_name, _NEWS, "OPT_IN", True, {explicit_in}, "D")

    # `alerts` default is OPT_IN and NOBODY expressed a preference for it, so the flag is the only
    # thing that can put anyone in either bucket.
    _assert_projection(sesv2, list_name, _ALERTS, "OPT_IN", False, set(), "E")
    _assert_projection(sesv2, list_name, _ALERTS, "OPT_IN", True, everyone, "F")
    _assert_projection(sesv2, list_name, _ALERTS, "OPT_OUT", True, set(), "G")

    # A filtered read must not advance any state, so repeated reads return the identical set.
    baseline = _projection(sesv2, list_name, _NEWS, "OPT_OUT", True)
    for attempt in range(_FREEZE_READS):
        repeat = _projection(sesv2, list_name, _NEWS, "OPT_OUT", True)
        assert repeat == baseline, (
            f"repeat read {attempt + 1} of the news/OPT_OUT/default-on projection returned "
            f"{sorted(repeat)}, expected the unchanged {sorted(baseline)} — a read advanced state"
        )


def _create_contact_list(ctx) -> str:
    """Create a contact list, or adopt the account's single existing list (SESv2 allows one per
    account), replacing its topics with ours and restoring them on cleanup."""
    sesv2 = ctx.client("sesv2")
    existing = _sole_existing_list(sesv2)
    if existing is None:
        name = ctx.unique_name("sim2real-behav-topicflag-")
        sesv2.create_contact_list(
            ContactListName=name,
            Topics=_TOPICS,
            Description="sim2real behavioral: UseDefaultIfPreferenceUnavailable isolation",
            Tags=[{"Key": "sim2real-managed", "Value": "true"}, {"Key": "sim2real-check", "Value": CHECK}],
        )
        ctx.on_cleanup(lambda: sesv2.delete_contact_list(ContactListName=name))
        return name

    # A list with no topics restores to no topics, so the empty default is correct here.
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


def _create_contact(ctx, list_name: str, prefix: str, preferences) -> str:
    sesv2 = ctx.client("sesv2")
    address = ctx.unique_name("sim2real-behav-" + prefix) + "@example.com"
    kwargs = {"ContactListName": list_name, "EmailAddress": address}
    if preferences:
        kwargs["TopicPreferences"] = [
            {"TopicName": topic, "SubscriptionStatus": status} for topic, status in preferences
        ]
    sesv2.create_contact(**kwargs)
    ctx.on_cleanup(
        lambda: sesv2.delete_contact(ContactListName=list_name, EmailAddress=address)
    )
    return address


def _all_contacts(sesv2, list_name: str, **filter_kwargs) -> set[str]:
    addresses: set[str] = set()
    token = None
    while True:
        kwargs = dict(filter_kwargs)
        kwargs["ContactListName"] = list_name
        if token:
            kwargs["NextToken"] = token
        page = sesv2.list_contacts(**kwargs)
        for contact in page.get("Contacts", []):
            addresses.add(contact["EmailAddress"])
        token = page.get("NextToken")
        if not token:
            break
    return addresses


def _await_all_visible(sesv2, list_name: str, expected: set[str]) -> set[str]:
    deadline = time.monotonic() + _SETTLE_DEADLINE_S
    seen: set[str] = set()
    while time.monotonic() < deadline:
        seen = _all_contacts(sesv2, list_name)
        if expected <= seen:
            return seen
        time.sleep(_SETTLE_INTERVAL_S)
    raise AssertionError(
        f"only {sorted(seen)} of the created contacts {sorted(expected)} became visible in "
        f"ListContacts within {_SETTLE_DEADLINE_S}s"
    )


def _projection(sesv2, list_name: str, topic: str, status: str, use_default: bool) -> set[str]:
    return _all_contacts(
        sesv2,
        list_name,
        Filter={
            "FilteredStatus": status,
            "TopicFilter": {"TopicName": topic, "UseDefaultIfPreferenceUnavailable": use_default},
        },
    )


def _assert_projection(sesv2, list_name, topic, status, use_default, expected, leg) -> None:
    actual = _projection(sesv2, list_name, topic, status, use_default)
    assert actual == expected, (
        f"leg {leg}: ListContacts(topic={topic}, FilteredStatus={status}, "
        f"UseDefaultIfPreferenceUnavailable={use_default}) returned {sorted(actual)}, "
        f"expected exactly {sorted(expected)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
