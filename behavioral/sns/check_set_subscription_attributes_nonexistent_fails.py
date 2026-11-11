"""set-subscription-attributes-nonexistent-fails."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-subscription-attributes-nonexistent-fails"
GROUP = 'subscription-lifecycle'
SERVICES = ['sns']


def _error(fn):
    """Call fn(); return the botocore error (Code, Message) if a ClientError was raised, else raise."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def _create_topic(ctx, name=None):
    """Create a topic, register its teardown, and return its ARN."""
    sns = ctx.client("sns")
    name = name or ctx.unique_name("sim2real-behav-sns-topic-")
    arn = sns.create_topic(Name=name)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


def _create_sqs_subscription(ctx, topic_arn):
    """Create an SQS queue and subscribe it to the topic; return the real, confirmed SubscriptionArn."""
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")
    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-sns-subattr-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))
    return sub_arn


def _fake_subscription_arn(topic_arn):
    """Return a well-formed but nonexistent SubscriptionArn for a topic."""
    return f"{topic_arn}:{uuid.uuid4()}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """[overly-permissive] SetSubscriptionAttributes on a nonexistent ARN must fail with NotFound, while
    the identical call against a real subscription succeeds and is independently readable back."""
    sns = ctx.client("sns")
    topic_arn = _create_topic(ctx)

    # Positive control: the real, existing subscription accepts the identical mutation, and an
    # independent read (GetSubscriptionAttributes, not the mutating SetSubscriptionAttributes
    # response) confirms it took effect.
    real_sub = _create_sqs_subscription(ctx, topic_arn)
    sns.set_subscription_attributes(
        SubscriptionArn=real_sub, AttributeName="RawMessageDelivery", AttributeValue="true"
    )
    control_attrs = sns.get_subscription_attributes(SubscriptionArn=real_sub)["Attributes"]
    assert control_attrs.get("RawMessageDelivery") == "true", (
        f"positive control: expected RawMessageDelivery='true' via independent read, got {control_attrs!r}"
    )

    # Break: a well-formed SubscriptionArn that was never created.
    fake_sub = _fake_subscription_arn(topic_arn)
    code, message = _error(
        lambda: sns.set_subscription_attributes(
            SubscriptionArn=fake_sub, AttributeName="RawMessageDelivery", AttributeValue="true"
        )
    )
    assert code == "NotFound", f"expected NotFound, got {code!r}"
    assert message == 'Subscription does not exist', (
        f"expected the exact message 'Subscription does not exist', got {message!r}"
    )

    # Effect absent, via an independent read at the destination (GetSubscriptionAttributes, a
    # different operation than the SetSubscriptionAttributes call under test).
    read_code, read_message = _error(lambda: sns.get_subscription_attributes(SubscriptionArn=fake_sub))
    assert read_code == "NotFound", (
        f"expected NotFound reading attributes of a nonexistent subscription, got {read_code!r}"
    )
    assert read_message == 'Subscription does not exist', (
        f"expected the exact message 'Subscription does not exist', got {read_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
