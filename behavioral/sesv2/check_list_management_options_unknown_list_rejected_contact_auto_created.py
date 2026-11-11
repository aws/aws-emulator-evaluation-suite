"""list-management-options-unknown-list-rejected-contact-auto-created."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-management-options-unknown-list-rejected-contact-auto-created"
GROUP = "contact-list"
SERVICES = ["sesv2"]

_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}
_TOPIC = "sim2real-topic"



def _dns_baseline_domain(ctx, route53, sesv2):
    """The account's DNS baseline domain, the apex of its public hosted zone tagged
    _BASELINE_TAG, which SES has verified."""
    for page in route53.get_paginator("list_hosted_zones").paginate():
        for z in page["HostedZones"]:
            if z["Config"].get("PrivateZone"):
                continue
            zone_tags = route53.list_tags_for_resource(
                ResourceType="hostedzone", ResourceId=z["Id"].rsplit("/", 1)[-1]
            )["ResourceTagSet"]["Tags"]
            if _BASELINE_TAG in zone_tags:
                domain = z["Name"].rstrip(".")
                identity = sesv2.get_email_identity(EmailIdentity=domain)
                assert identity["VerifiedForSendingStatus"], (
                    f"the DNS baseline domain {domain!r} is not verified in {ctx.region}"
                )
                return domain
    raise AssertionError(
        "no public hosted zone carries the DNS baseline tag, so the account has "
        "no verified domain to send from"
    )


def _error(fn) -> tuple[str, str]:
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError("expected the call to be refused, but it succeeded")


def _clear_contact_lists(sesv2) -> None:
    """Delete any existing contact list: SES allows one per account per region and refuses a
    second CreateContactList."""
    for entry in sesv2.list_contact_lists().get("ContactLists", []):
        sesv2.delete_contact_list(ContactListName=entry["ContactListName"])




@tags("resource:account-singleton:sesv2-contact-list", "axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data", "requires:dns-baseline")
def run(ctx) -> None:
    """SendEmail with ListManagementOptions naming an unknown contact list is refused with
    NotFoundException; against a real list it auto-creates the recipient as a contact, with
    TopicPreferences only when a TopicName is given.
    """
    route53 = ctx.client("route53")
    sesv2 = ctx.client("sesv2")
    domain = _dns_baseline_domain(ctx, route53, sesv2)
    sender = f"{ctx.unique_name('sim2real-behav-')}@{domain}"

    def _content(subject: str) -> dict:
        return {"Simple": {"Subject": {"Data": subject}, "Body": {"Text": {"Data": "probe"}}}}

    # Break exactly one thing: the contact list does not exist. The sender is verified (via the
    # baseline domain) and the recipient is otherwise unremarkable, isolating the list lookup.
    absent_list = ctx.unique_name("sim2real-behav-absent-list-")
    absent_recipient = f"{ctx.unique_name('sim2real-behav-')}@{domain}"
    refused = _error(
        lambda: sesv2.send_email(
            FromEmailAddress=sender,
            Destination={"ToAddresses": [absent_recipient]},
            Content=_content("sim2real list-management probe (absent list)"),
            ListManagementOptions={"ContactListName": absent_list},
        )
    )
    expected_refused = ("NotFoundException", f"List with name: {absent_list} doesn't exist.")
    assert refused == expected_refused, (
        f"SendEmail naming a contact list that does not exist must be refused "
        f"{expected_refused!r}; got {refused!r}"
    )

    # Effect absent: the refused call created neither a contact list nor a contact anywhere.
    existing_lists: set[str] = set()
    token = None
    for _ in range(60):
        resp = sesv2.list_contact_lists(**({"NextToken": token} if token else {}))
        existing_lists.update(e["ContactListName"] for e in resp.get("ContactLists", []))
        token = resp.get("NextToken")
        if not token:
            break
    assert absent_list not in existing_lists, (
        f"a refused SendEmail must not have created the contact list {absent_list!r} it named"
    )

    # Positive control: the SAME mechanism against a real list, with a TopicName, auto-creates
    # the destination as a contact subscribed to that topic.
    contact_list = ctx.unique_name("sim2real-behav-cl-")
    _clear_contact_lists(sesv2)
    sesv2.create_contact_list(
        ContactListName=contact_list,
        Topics=[{"TopicName": _TOPIC, "DisplayName": "sim2real", "DefaultSubscriptionStatus": "OPT_IN"}],
        Tags=[
            {"Key": "sim2real-managed", "Value": "true"},
            {"Key": "sim2real-check", "Value": CHECK},
        ],
    )
    ctx.on_cleanup(lambda: sesv2.delete_contact_list(ContactListName=contact_list))

    with_topic_recipient = f"{ctx.unique_name('sim2real-behav-')}@{domain}"
    pre = _error(
        lambda: sesv2.get_contact(ContactListName=contact_list, EmailAddress=with_topic_recipient)
    )
    expected_pre = ("NotFoundException", f"{with_topic_recipient} doesn't exist in List.")
    assert pre == expected_pre, (
        f"setup precondition: the recipient must not already be a contact, refused "
        f"{expected_pre!r}; got {pre!r}"
    )
    sesv2.send_email(
        FromEmailAddress=sender,
        Destination={"ToAddresses": [with_topic_recipient]},
        Content=_content("sim2real list-management probe (with topic)"),
        ListManagementOptions={"ContactListName": contact_list, "TopicName": _TOPIC},
    )
    created = sesv2.get_contact(ContactListName=contact_list, EmailAddress=with_topic_recipient)
    assert created["EmailAddress"] == with_topic_recipient, (
        f"the recipient must have been auto-created as a contact; got {created!r}"
    )
    topic_names = {t["TopicName"] for t in created.get("TopicPreferences") or []}
    assert topic_names == {_TOPIC}, (
        f"the auto-created contact must carry a TopicPreferences entry for {_TOPIC!r}; got "
        f"{created.get('TopicPreferences')!r}"
    )

    # Positive control, variant: TopicName is OPTIONAL. The same mechanism without one still
    # auto-creates the contact, with no topic subscription recorded.
    no_topic_recipient = f"{ctx.unique_name('sim2real-behav-')}@{domain}"
    sesv2.send_email(
        FromEmailAddress=sender,
        Destination={"ToAddresses": [no_topic_recipient]},
        Content=_content("sim2real list-management probe (no topic)"),
        ListManagementOptions={"ContactListName": contact_list},
    )
    created_no_topic = sesv2.get_contact(ContactListName=contact_list, EmailAddress=no_topic_recipient)
    assert created_no_topic["EmailAddress"] == no_topic_recipient, (
        f"a ListManagementOptions call with no TopicName must still auto-create the contact; "
        f"got {created_no_topic!r}"
    )
    assert not created_no_topic.get("TopicPreferences"), (
        f"with no TopicName given, the auto-created contact must carry no topic subscription; "
        f"got {created_no_topic.get('TopicPreferences')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
