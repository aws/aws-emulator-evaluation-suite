"""contact-list-create-limit-boundaries."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "contact-list-create-limit-boundaries"
GROUP = "contact-list"
SERVICES = ["sesv2"]


def _error(fn):
    """Return the (code, message) of the ClientError fn raises; raise if fn succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return (err.get("Code"), err.get("Message"))
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


def expect_error(fn, code, message):
    got = _error(fn)
    assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"


def _topic(i: int) -> dict:
    return {
        "TopicName": f"topic-{i}",
        "DisplayName": f"Topic {i}",
        "DefaultSubscriptionStatus": "OPT_IN",
    }


def _restore(ses, prior):
    """Teardown: recreate the account's prior contact list exactly as it was read."""

    def run_restore() -> None:
        if prior is None:
            return
        kwargs = {"ContactListName": prior["ContactListName"]}
        if prior.get("Description") is not None:
            kwargs["Description"] = prior["Description"]
        if prior.get("Topics"):
            kwargs["Topics"] = prior["Topics"]
        if prior.get("Tags"):
            kwargs["Tags"] = prior["Tags"]
        ses.create_contact_list(**kwargs)

    return run_restore


@tags(
    "resource:account-singleton:sesv2-contact-list",
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A ContactList created at the exact description-length and topic-count boundaries round-trips
    verbatim; one past either boundary, a duplicate topic name, and a second list while one
    already exists are each refused with their exact message and create nothing."""
    ses = ctx.client("sesv2")

    existing = ses.list_contact_lists().get("ContactLists", [])
    prior = None
    if existing:
        prior_name = existing[0]["ContactListName"]
        prior = ses.get_contact_list(ContactListName=prior_name)
        ses.delete_contact_list(ContactListName=prior_name)
    ctx.on_cleanup(_restore(ses, prior))

    boundary_name = ctx.unique_name("sim2real-behav-clist-")
    boundary_description = "x" * 500
    boundary_topics = [_topic(i) for i in range(20)]
    ses.create_contact_list(
        ContactListName=boundary_name,
        Description=boundary_description,
        Topics=boundary_topics,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ses.delete_contact_list(ContactListName=boundary_name))

    got = ses.get_contact_list(ContactListName=boundary_name)
    assert got["Description"] == boundary_description, (
        f"expected the 500-char boundary Description to round-trip verbatim, got "
        f"{len(got['Description'])} chars"
    )
    assert got["Topics"] == boundary_topics, (
        f"expected the 20-topic boundary to round-trip verbatim, got {got['Topics']!r}"
    )

    _DESC_TOO_LONG = ("BadRequestException", "List description can contain up to 500 characters.")
    _TOO_MANY_TOPICS = ("BadRequestException", "Maximum of <20> topics allowed per ContactList")
    _DUPLICATE_TOPICS = (
        "BadRequestException",
        "Duplicate topic names are not allowed within a List.",
    )
    _SECOND_LIST = ("BadRequestException", "A maximum of 1 Lists allowed per account.")

    def assert_absent(name: str) -> None:
        expected = ("NotFoundException", f"List with name: {name} doesn't exist.")
        err = _error(lambda: ses.get_contact_list(ContactListName=name))
        assert err == expected, f"expected {expected!r} for a never-created list, got {err!r}"

    rejected_name = ctx.unique_name("sim2real-behav-clist-")

    expect_error(
        lambda: ses.create_contact_list(ContactListName=rejected_name, Description="x" * 501),
        *_DESC_TOO_LONG,
    )
    assert_absent(rejected_name)

    expect_error(
        lambda: ses.create_contact_list(
            ContactListName=rejected_name, Topics=[_topic(i) for i in range(21)]
        ),
        *_TOO_MANY_TOPICS,
    )
    assert_absent(rejected_name)

    expect_error(
        lambda: ses.create_contact_list(
            ContactListName=rejected_name, Topics=[_topic(0), _topic(0)]
        ),
        *_DUPLICATE_TOPICS,
    )
    assert_absent(rejected_name)

    expect_error(
        lambda: ses.create_contact_list(ContactListName=rejected_name), *_SECOND_LIST
    )
    assert_absent(rejected_name)

    # Positive control: the four refused attempts above left the existing list untouched.
    still_there = ses.get_contact_list(ContactListName=boundary_name)
    assert still_there["Description"] == boundary_description, (
        "the boundary list's Description changed after the rejected creates, expected it "
        "untouched"
    )
    assert still_there["Topics"] == boundary_topics, (
        "the boundary list's Topics changed after the rejected creates, expected them untouched"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
