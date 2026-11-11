"""unsubscribe-all-overrides-an-explicit-topic-optin-without-erasing-it."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "unsubscribe-all-overrides-an-explicit-topic-optin-without-erasing-it"
GROUP = "contact-list"
SERVICES = ["sesv2"]

_TOPIC = "promos"
_TOPICS = [{"TopicName": _TOPIC, "DisplayName": "Promotions", "DefaultSubscriptionStatus": "OPT_OUT"}]
#: Reason for the wait: UpdateContact is a write and ListContacts is a separate read path.
#: Raises on timeout.
_SETTLE_DEADLINE_S = 60.0
_SETTLE_INTERVAL_S = 2.0


@tags("resource:account-singleton:sesv2-contact-list", "axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UnsubscribeAll=True moves one contact from a topic's OPT_IN to its OPT_OUT ListContacts
    projection while an identical twin stays put; the stored OPT_IN preference survives, and
    clearing the flag restores the OPT_IN projection.
    """
    sesv2 = ctx.client("sesv2")
    list_name = _create_contact_list(ctx)

    subject = _create_contact(ctx, list_name, "subject-")
    twin = _create_contact(ctx, list_name, "twin-")

    # Beat 1 — positive control: both contacts sit in the topic's OPT_IN projection.
    _await_projection(sesv2, list_name, "OPT_IN", {subject, twin}, "positive control")
    _assert_projection(sesv2, list_name, "OPT_OUT", set(), "positive control")

    # Beat 2 — break exactly one thing on exactly one contact.
    sesv2.update_contact(ContactListName=list_name, EmailAddress=subject, UnsubscribeAll=True)

    # Beat 3 — the specific effect, and Beat 4 — the twin is unaffected in the same instant.
    _await_projection(sesv2, list_name, "OPT_IN", {twin}, "after UnsubscribeAll=True on subject")
    _assert_projection(
        sesv2, list_name, "OPT_OUT", {subject}, "after UnsubscribeAll=True on subject"
    )

    # The override is evaluated at read time, not destructive: the stored preference stays OPT_IN.
    stored = sesv2.get_contact(ContactListName=list_name, EmailAddress=subject)
    assert stored["UnsubscribeAll"] is True, (
        f"GetContact reports UnsubscribeAll={stored.get('UnsubscribeAll')!r} for {subject} after "
        f"UpdateContact set it True"
    )
    preferences = {p["TopicName"]: p["SubscriptionStatus"] for p in stored["TopicPreferences"]}
    assert preferences.get(_TOPIC) == "OPT_IN", (
        f"UnsubscribeAll=True erased the stored per-topic preference for {subject}: GetContact "
        f"reports TopicPreferences={preferences!r}, expected {_TOPIC}=OPT_IN to survive because the "
        f"override is evaluated at read time"
    )
    twin_stored = sesv2.get_contact(ContactListName=list_name, EmailAddress=twin)
    assert twin_stored["UnsubscribeAll"] is False, (
        f"the twin {twin} was never updated but GetContact reports "
        f"UnsubscribeAll={twin_stored.get('UnsubscribeAll')!r}, expected False"
    )

    # Beats 5 and 6 — restore the one broken thing, and demand the original projection back.
    sesv2.update_contact(ContactListName=list_name, EmailAddress=subject, UnsubscribeAll=False)
    _await_projection(sesv2, list_name, "OPT_IN", {subject, twin}, "after UnsubscribeAll=False")
    _assert_projection(sesv2, list_name, "OPT_OUT", set(), "after UnsubscribeAll=False")
    restored = sesv2.get_contact(ContactListName=list_name, EmailAddress=subject)
    restored_prefs = {p["TopicName"]: p["SubscriptionStatus"] for p in restored["TopicPreferences"]}
    assert restored_prefs.get(_TOPIC) == "OPT_IN", (
        f"after clearing UnsubscribeAll the stored preference for {subject} is "
        f"{restored_prefs!r}, expected {_TOPIC}=OPT_IN"
    )


def _create_contact_list(ctx) -> str:
    """Create-or-adopt. SESv2 permits one contact list per account per region, so an existing list
    is adopted and its topic set restored on cleanup rather than deleted."""
    sesv2 = ctx.client("sesv2")
    existing = _sole_existing_list(sesv2)
    if existing is None:
        name = ctx.unique_name("sim2real-behav-unsuball-")
        sesv2.create_contact_list(
            ContactListName=name,
            Topics=_TOPICS,
            Description="sim2real behavioral: UnsubscribeAll override",
            Tags=[
                {"Key": "sim2real-managed", "Value": "true"},
                {"Key": "sim2real-check", "Value": CHECK},
            ],
        )
        ctx.on_cleanup(lambda: sesv2.delete_contact_list(ContactListName=name))
        return name

    # On the restore path, not an assertion path: a list that genuinely has no topics restores to
    # no topics, so the empty default is the correct semantics here.
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


def _create_contact(ctx, list_name: str, prefix: str) -> str:
    """Both contacts are created identically: an explicit OPT_IN on the topic, UnsubscribeAll off.
    They differ in nothing but their address until one is deliberately changed."""
    sesv2 = ctx.client("sesv2")
    address = ctx.unique_name("sim2real-behav-" + prefix) + "@example.com"
    sesv2.create_contact(
        ContactListName=list_name,
        EmailAddress=address,
        TopicPreferences=[{"TopicName": _TOPIC, "SubscriptionStatus": "OPT_IN"}],
        UnsubscribeAll=False,
    )
    ctx.on_cleanup(lambda: sesv2.delete_contact(ContactListName=list_name, EmailAddress=address))
    return address


def _projection(sesv2, list_name: str, status: str) -> set[str]:
    """The topic's OPT_IN / OPT_OUT projection with defaults switched OFF, so only explicit
    preferences and the unsubscribe-all override can place a contact in either bucket."""
    addresses: set[str] = set()
    token = None
    while True:
        kwargs = {
            "ContactListName": list_name,
            "Filter": {
                "FilteredStatus": status,
                "TopicFilter": {
                    "TopicName": _TOPIC,
                    "UseDefaultIfPreferenceUnavailable": False,
                },
            },
        }
        if token:
            kwargs["NextToken"] = token
        page = sesv2.list_contacts(**kwargs)
        for contact in page.get("Contacts", []):
            addresses.add(contact["EmailAddress"])
        token = page.get("NextToken")
        if not token:
            break
    return addresses


def _await_projection(sesv2, list_name: str, status: str, expected: set[str], phase: str) -> None:
    deadline = time.monotonic() + _SETTLE_DEADLINE_S
    actual: set[str] = set()
    while time.monotonic() < deadline:
        actual = _projection(sesv2, list_name, status)
        if actual == expected:
            return
        time.sleep(_SETTLE_INTERVAL_S)
    raise AssertionError(
        f"{phase}: the {_TOPIC}/{status} projection never became exactly {sorted(expected)} "
        f"within {_SETTLE_DEADLINE_S}s (last={sorted(actual)})"
    )


def _assert_projection(sesv2, list_name: str, status: str, expected: set[str], phase: str) -> None:
    actual = _projection(sesv2, list_name, status)
    assert actual == expected, (
        f"{phase}: the {_TOPIC}/{status} projection is {sorted(actual)}, expected exactly "
        f"{sorted(expected)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
