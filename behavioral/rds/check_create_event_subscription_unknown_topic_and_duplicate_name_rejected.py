"""create-event-subscription-unknown-topic-and-duplicate-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-event-subscription-unknown-topic-and-duplicate-name-rejected"
GROUP = "events"
SERVICES = ["rds", "sns"]

ERR_TOPIC_NOT_FOUND = "SNSTopicArnNotFound"
ERR_ALREADY_EXISTS = "SubscriptionAlreadyExist"


def _error_code(fn):
    """The (code, message) ``fn`` raises; an unexpected success raises, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEventSubscription rejects a well-formed but never-created SNS topic ARN with
    SNSTopicArnNotFound, and rejects a subscription name already in use with
    SubscriptionAlreadyExist; the same name with a real topic succeeds."""
    rds = ctx.client("rds")
    sns = ctx.client("sns")

    bogus_topic_name = ctx.unique_name("sim2real-behav-topic-missing-")
    bogus_topic_arn = f"arn:aws:sns:{ctx.region}:{ctx.account}:{bogus_topic_name}"
    sub_name = ctx.unique_name("sim2real-behav-evsub-")

    code, message = _error_code(
        lambda: rds.create_event_subscription(
            SubscriptionName=sub_name,
            SnsTopicArn=bogus_topic_arn,
            SourceType="db-instance",
        )
    )
    assert code == ERR_TOPIC_NOT_FOUND, f"unexpected error code: {code!r}"
    expected = f"Failed to create Subscription because of Topic {bogus_topic_arn} Not Found."
    assert message == expected, f"unexpected message: {message!r} (expected {expected!r})"

    # Effect absent: the rejected subscription was never created.
    not_found_code, _ = _error_code(
        lambda: rds.describe_event_subscriptions(SubscriptionName=sub_name)
    )
    assert not_found_code == "SubscriptionNotFound", (
        f"expected SubscriptionNotFound for a never-created name, got {not_found_code!r}"
    )

    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-topic-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    rds.create_event_subscription(
        SubscriptionName=sub_name, SnsTopicArn=topic_arn, SourceType="db-instance"
    )
    ctx.on_cleanup(lambda: _safe_delete_subscription(rds, sub_name))

    dup_code, dup_message = _error_code(
        lambda: rds.create_event_subscription(
            SubscriptionName=sub_name, SnsTopicArn=topic_arn, SourceType="db-instance"
        )
    )
    assert dup_code == ERR_ALREADY_EXISTS, f"unexpected error code: {dup_code!r}"
    expected_dup = "Subscription already exists"
    assert dup_message == expected_dup, f"unexpected message: {dup_message!r} (expected {expected_dup!r})"


def _safe_delete_subscription(rds, sub_name: str) -> None:
    try:
        rds.delete_event_subscription(SubscriptionName=sub_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "SubscriptionNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
