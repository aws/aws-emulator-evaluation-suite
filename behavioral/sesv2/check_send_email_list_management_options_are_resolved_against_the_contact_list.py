"""send-email-list-management-options-are-resolved-against-the-contact-list."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-email-list-management-options-are-resolved-against-the-contact-list"
GROUP = "contact-list"
SERVICES = ["sesv2"]

_SIMULATOR = "success@simulator.amazonses.com"
_TOPIC = "newsletter"
_TOPICS = [
    {"TopicName": _TOPIC, "DisplayName": "Newsletter", "DefaultSubscriptionStatus": "OPT_IN"}
]


@tags("resource:account-singleton:sesv2-contact-list", "axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendEmail resolves ListManagementOptions against the contact list before the sender gate:
    a valid pair yields MessageRejected, an unknown topic or list its own NotFoundException.
    """
    sesv2 = ctx.client("sesv2")
    list_name = _create_contact_list(ctx)
    unverified = ctx.unique_name("sim2real-behav-unverified-") + "@example.com"
    absent_list = ctx.unique_name("sim2real-behav-absent-list-")
    absent_topic = ctx.unique_name("sim2real-behav-absent-topic-")

    # Beat 1 — positive control, via an independent read on a different operation than the create.
    described = sesv2.get_contact_list(ContactListName=list_name)
    topic_names = {topic["TopicName"] for topic in described["Topics"]}
    assert topic_names == {_TOPIC}, (
        f"positive control failed: GetContactList({list_name}) reports topics {sorted(topic_names)}, "
        f"expected exactly {{{_TOPIC!r}}}"
    )

    # Beat 2 — the baseline refusal: list and topic are both real, only the sender is not.
    valid_code, valid_message = _send_error(
        sesv2, unverified, {"ContactListName": list_name, "TopicName": _TOPIC}
    )
    expected_rejected = (
        "MessageRejected",
        "Email address is not verified. The following identities failed the check in region "
        f"{ctx.region.upper()}: {unverified}",
    )
    assert (valid_code, valid_message) == expected_rejected, (
        f"SendEmail with a valid ListManagementOptions pair and an unverified sender returned "
        f"{(valid_code, valid_message)!r}, expected {expected_rejected!r} (the identity gate)"
    )

    # Beat 3 — break exactly one field: the topic. The list is unchanged and still real.
    bad_topic_code, bad_topic_message = _send_error(
        sesv2, unverified, {"ContactListName": list_name, "TopicName": absent_topic}
    )
    expected_bad_topic = (
        "NotFoundException",
        f"List: {list_name} doesn't contain Topic: {absent_topic}",
    )
    assert (bad_topic_code, bad_topic_message) == expected_bad_topic, (
        f"SendEmail naming topic {absent_topic!r}, which is not on contact list {list_name} "
        f"(topics={sorted(topic_names)}), returned {(bad_topic_code, bad_topic_message)!r}, "
        f"expected {expected_bad_topic!r}; the identical call with topic {_TOPIC!r} returned "
        f"{valid_code!r}"
    )

    # Beat 4 — break the other field instead: the list.
    bad_list_code, bad_list_message = _send_error(
        sesv2, unverified, {"ContactListName": absent_list, "TopicName": _TOPIC}
    )
    expected_bad_list = ("NotFoundException", f"List with name: {absent_list} doesn't exist.")
    assert (bad_list_code, bad_list_message) == expected_bad_list, (
        f"SendEmail naming contact list {absent_list!r}, which does not exist, returned "
        f"{(bad_list_code, bad_list_message)!r}, expected {expected_bad_list!r}"
    )

    # Effect-absent: the list SendEmail refused genuinely does not exist, read independently.
    absent = _error(lambda: sesv2.get_contact_list(ContactListName=absent_list))
    expected_absent = ("NotFoundException", f"List with name: {absent_list} doesn't exist.")
    assert absent == expected_absent, (
        f"GetContactList({absent_list}) returned {absent!r}, expected {expected_absent!r}"
    )

    # Beats 5 and 6 — restore and demand the unchanged baseline, then re-confirm the list survived
    # the refused sends untouched.
    restored = _send_error(
        sesv2, unverified, {"ContactListName": list_name, "TopicName": _TOPIC}
    )
    assert restored == expected_rejected, (
        f"after the two broken variants the original SendEmail returned {restored!r} instead "
        f"of the unchanged {expected_rejected!r}"
    )
    after = sesv2.get_contact_list(ContactListName=list_name)
    after_topics = {topic["TopicName"] for topic in after["Topics"]}
    assert after_topics == topic_names, (
        f"contact list {list_name} topics changed across the refused sends: {sorted(after_topics)} "
        f"vs the original {sorted(topic_names)}"
    )

    _assert_codes_are_not_all_equal(
        {
            "valid-list-and-topic": valid_code,
            "unknown-topic": bad_topic_code,
            "unknown-list": bad_list_code,
        }
    )


def _create_contact_list(ctx) -> str:
    """Create-or-adopt. SESv2 permits one contact list per account per region, so an existing list is
    adopted and its topic set restored on cleanup rather than deleted."""
    sesv2 = ctx.client("sesv2")
    existing = _sole_existing_list(sesv2)
    if existing is None:
        name = ctx.unique_name("sim2real-behav-listmgmt-")
        sesv2.create_contact_list(
            ContactListName=name,
            Topics=_TOPICS,
            Description="sim2real behavioral: SendEmail ListManagementOptions resolution",
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


def _send_error(sesv2, sender: str, list_management: dict) -> tuple:
    return _error(
        lambda: sesv2.send_email(
            FromEmailAddress=sender,
            Destination={"ToAddresses": [_SIMULATOR]},
            Content={
                "Simple": {
                    "Subject": {"Data": "sim2real list-management probe"},
                    "Body": {"Text": {"Data": "sim2real list-management probe body"}},
                }
            },
            ListManagementOptions=list_management,
        )
    )


def _error(fn) -> tuple:
    """Returns the ClientError (code, message)."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        "the call succeeded where a refusal was required; an unverified sender, an unknown contact "
        "list or an unknown topic must never produce a 200"
    )


def _assert_codes_are_not_all_equal(codes: dict[str, str]) -> None:
    """Backstop: a target that answers every SendEmail refusal with one code is not resolving
    the contact list at all."""
    distinct = set(codes.values())
    assert len(distinct) > 1, (
        f"SendEmail returned the single code {distinct.pop()!r} for all three deliberately "
        f"different ListManagementOptions faults {codes!r}; it is not resolving the contact list "
        f"or the topic at all"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
