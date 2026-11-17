"""update-contact-list-over-topic-limit-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-contact-list-over-topic-limit-rejected"
GROUP = "sesv2"
SERVICES = ["sesv2"]


def _topic(name: str, display: str) -> dict:
    return {"TopicName": name, "DisplayName": display, "DefaultSubscriptionStatus": "OPT_IN"}


def expect_error(fn, code: str, message: str) -> None:
    """Assert fn raises a ClientError with exactly this code and message."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == code, f"expected error code {code!r}, got {err['Code']!r}"
        assert err["Message"] == message, f"expected message {message!r}, got {err['Message']!r}"
        return
    raise AssertionError(f"expected {code!r}, but the call succeeded with {result!r}")


_OVER_LIMIT = (
    "BadRequestException",
    "Maximum of <20> topics allowed per ContactList",
)


@tags(
    "resource:account-singleton:sesv2-contact-list",
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """UpdateContactList refuses 21 topics and leaves the stored topics and
    description unchanged; a 20-topic update to the same list then applies.
    """
    ses = ctx.client("sesv2")

    existing = ses.list_contact_lists().get("ContactLists", [])
    if existing:
        list_name = existing[0]["ContactListName"]
        prior = ses.get_contact_list(ContactListName=list_name)
        prior_topics = prior.get("Topics", [])
        prior_description = prior.get("Description")

        def _restore():
            kwargs = {"ContactListName": list_name, "Topics": prior_topics}
            if prior_description is not None:
                kwargs["Description"] = prior_description
            ses.update_contact_list(**kwargs)

        ctx.on_cleanup(_restore)
    else:
        list_name = ctx.unique_name("sim2real-contact-list-")
        ses.create_contact_list(ContactListName=list_name)
        ctx.on_cleanup(lambda: ses.delete_contact_list(ContactListName=list_name))

    baseline_topics = [_topic(f"topic-{i}", f"Topic {i}") for i in range(5)]
    baseline_description = "pre-refusal baseline"
    ses.update_contact_list(
        ContactListName=list_name, Topics=baseline_topics, Description=baseline_description
    )
    baseline = ses.get_contact_list(ContactListName=list_name)
    assert baseline["Topics"] == baseline_topics, (
        f"baseline update did not store the topics it sent: {baseline['Topics']!r}"
    )
    assert baseline["Description"] == baseline_description, (
        f"baseline update did not store its description: {baseline['Description']!r}"
    )

    over_limit_topics = [_topic(f"topic-{i}", f"Topic {i}") for i in range(21)]
    expect_error(
        lambda: ses.update_contact_list(
            ContactListName=list_name,
            Topics=over_limit_topics,
            Description="refused update, must not persist",
        ),
        *_OVER_LIMIT,
    )

    after_refusal = ses.get_contact_list(ContactListName=list_name)
    assert after_refusal["Topics"] == baseline_topics, (
        f"the refused update changed the stored topics: {after_refusal['Topics']!r}"
    )
    assert after_refusal["Description"] == baseline_description, (
        f"the refused update changed the stored description: {after_refusal['Description']!r}"
    )

    within_limit_topics = [_topic(f"topic-{i}", f"Topic {i}") for i in range(20)]
    within_limit_description = "within-limit update applied"
    ses.update_contact_list(
        ContactListName=list_name, Topics=within_limit_topics, Description=within_limit_description
    )
    after_within_limit = ses.get_contact_list(ContactListName=list_name)
    assert after_within_limit["Topics"] == within_limit_topics, (
        f"a 20-topic update did not apply: {after_within_limit['Topics']!r}"
    )
    assert after_within_limit["Description"] == within_limit_description, (
        f"a 20-topic update did not apply its description: {after_within_limit['Description']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
