"""modify-event-subscription-severity-category-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-event-subscription-severity-category-rejected"
GROUP = "eventing"
SERVICES = ["redshift", "sns"]


def _error(fn):
    """Call fn(); return (code, message) of its ClientError; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError rejection but the call succeeded: {result!r}")


def _ignore_missing(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "SubscriptionNotFound":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyEventSubscription rejects an unknown Severity and an unknown EventCategories entry,
    each with its own fault, and leaves the subscription's prior values unchanged; a later
    modify with valid values for both fields succeeds.
    """
    rs = ctx.client("redshift")
    sns = ctx.client("sns")

    topic_name = ctx.unique_name("sim2real-behav-rs-modevsubval-topic-")
    topic_arn = sns.create_topic(
        Name=topic_name, Tags=[{"Key": "sim2real-behavioral", "Value": "true"}]
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    name = ctx.unique_name("sim2real-behav-rs-modevsubval-")
    rs.create_event_subscription(
        SubscriptionName=name,
        SnsTopicArn=topic_arn,
        SourceType="cluster",
        Severity="INFO",
        EventCategories=["configuration"],
    )
    ctx.on_cleanup(
        lambda: _ignore_missing(lambda: rs.delete_event_subscription(SubscriptionName=name))
    )

    code, message = _error(lambda: rs.modify_event_subscription(
        SubscriptionName=name, Severity="CRITICAL"
    ))
    assert (code, message) == (
        "SubscriptionSeverityNotFound", "Severity 'CRITICAL' was not recognized."
    ), f"expected a SubscriptionSeverityNotFound rejection, got {code}: {message!r}"
    unaffected = rs.describe_event_subscriptions(SubscriptionName=name)[
        "EventSubscriptionsList"
    ][0]
    assert unaffected["Severity"] == "INFO", (
        f"a rejected Severity modify must not change the stored value, got {unaffected['Severity']!r}"
    )

    code, message = _error(lambda: rs.modify_event_subscription(
        SubscriptionName=name, EventCategories=["not-a-category"]
    ))
    assert (code, message) == (
        "SubscriptionCategoryNotFound", "Category 'not-a-category' was not recognized."
    ), f"expected a SubscriptionCategoryNotFound rejection, got {code}: {message!r}"
    unaffected = rs.describe_event_subscriptions(SubscriptionName=name)[
        "EventSubscriptionsList"
    ][0]
    assert unaffected["EventCategoriesList"] == ["configuration"], (
        f"a rejected EventCategories modify must not change the stored value, "
        f"got {unaffected['EventCategoriesList']!r}"
    )

    modified = rs.modify_event_subscription(
        SubscriptionName=name, Severity="ERROR", EventCategories=["monitoring"]
    )["EventSubscription"]
    assert modified["Severity"] == "ERROR", (
        f"a valid Severity modify must take effect, got {modified['Severity']!r}"
    )
    assert modified["EventCategoriesList"] == ["monitoring"], (
        f"a valid EventCategories modify must take effect, got {modified['EventCategoriesList']!r}"
    )
    confirmed = rs.describe_event_subscriptions(SubscriptionName=name)[
        "EventSubscriptionsList"
    ][0]
    assert (confirmed["Severity"], confirmed["EventCategoriesList"]) == ("ERROR", ["monitoring"]), (
        f"an independent read must confirm the valid modify, got "
        f"{(confirmed['Severity'], confirmed['EventCategoriesList'])!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
