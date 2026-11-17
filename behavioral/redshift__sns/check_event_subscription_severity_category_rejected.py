"""event-subscription-severity-category-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "event-subscription-severity-category-rejected"
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
    """CreateEventSubscription rejects an unknown Severity and an unknown EventCategories entry,
    each with its own fault, and leaves no subscription behind; the same request with every
    field valid succeeds.
    """
    rs = ctx.client("redshift")
    sns = ctx.client("sns")

    topic_name = ctx.unique_name("sim2real-behav-rs-evsubval-topic-")
    topic_arn = sns.create_topic(
        Name=topic_name, Tags=[{"Key": "sim2real-behavioral", "Value": "true"}]
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    valid_name = ctx.unique_name("sim2real-behav-rs-evsubval-ok-")
    control = rs.create_event_subscription(
        SubscriptionName=valid_name,
        SnsTopicArn=topic_arn,
        SourceType="cluster",
        Severity="INFO",
        EventCategories=["configuration"],
    )["EventSubscription"]
    ctx.on_cleanup(
        lambda: _ignore_missing(lambda: rs.delete_event_subscription(SubscriptionName=valid_name))
    )
    assert control["Severity"] == "INFO", f"expected Severity 'INFO', got {control['Severity']!r}"
    assert control["EventCategoriesList"] == ["configuration"], (
        f"expected EventCategoriesList ['configuration'], got {control['EventCategoriesList']!r}"
    )

    described = rs.describe_event_subscriptions(SubscriptionName=valid_name)[
        "EventSubscriptionsList"
    ]
    assert len(described) == 1 and described[0]["Severity"] == "INFO", (
        f"expected exactly one subscription named {valid_name!r} with Severity 'INFO', got {described!r}"
    )

    cases = {
        "bad-severity": (
            ctx.unique_name("sim2real-behav-rs-evsubval-sev-"),
            {"SourceType": "cluster", "Severity": "CRITICAL", "EventCategories": ["configuration"]},
        ),
        "bad-category": (
            ctx.unique_name("sim2real-behav-rs-evsubval-cat-"),
            {"SourceType": "cluster", "Severity": "INFO", "EventCategories": ["not-a-category"]},
        ),
    }
    expected = {
        "bad-severity": ("SubscriptionSeverityNotFound", "Severity 'CRITICAL' was not recognized."),
        "bad-category": ("SubscriptionCategoryNotFound", "Category 'not-a-category' was not recognized."),
    }
    observed = {}
    for label, (name, extra) in cases.items():
        observed[label] = _error(lambda name=name, extra=extra: rs.create_event_subscription(
            SubscriptionName=name, SnsTopicArn=topic_arn, **extra
        ))
    assert observed == expected, (
        f"event-subscription validation contract drift:\n expected={expected}\n observed={observed}"
    )

    for label, (name, _) in cases.items():
        lookup, lookup_message = _error(
            lambda name=name: rs.describe_event_subscriptions(SubscriptionName=name)
        )
        assert lookup == "SubscriptionNotFound", (
            f"{label}: a rejected create must not leave a subscription behind, got {lookup}"
        )
        assert lookup_message == f"Event Subscription {name} not found", (
            f"{label}: expected the not-found message for {name!r}, got {lookup_message!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
