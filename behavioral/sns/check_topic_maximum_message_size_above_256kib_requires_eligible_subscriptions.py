"""topic-maximum-message-size-above-256kib-requires-eligible-subscriptions."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "topic-maximum-message-size-above-256kib-requires-eligible-subscriptions"
GROUP = 'topic-attributes'
SERVICES = ['sns']

_OVER_256_KIB = 300000


def _error(fn):
    """Return (Error.Code, Error.Message) of the ClientError fn raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """MaximumMessageSize above 256 KiB is refused InvalidParameter (left unset) while the topic
    has a non-SQS/Firehose/Lambda subscription, even a pending one; a topic whose only
    subscription is SQS accepts the same value.
    """
    sns = ctx.client("sns")

    ineligible_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-sns-maxmsg-inel-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=ineligible_arn))
    email = f"{ctx.unique_name('sim2real-behav-sns-maxmsg')}@example.com"
    # Email subscriptions stay PendingConfirmation forever without a real mailbox; DeleteTopic
    # (registered above) removes it, since a pending subscription cannot be Unsubscribed.
    sns.subscribe(TopicArn=ineligible_arn, Protocol="email", Endpoint=email)

    code, message = _error(lambda: sns.set_topic_attributes(
        TopicArn=ineligible_arn, AttributeName="MaximumMessageSize", AttributeValue=str(_OVER_256_KIB)))
    assert code == "InvalidParameter", (
        f"raising MaximumMessageSize past 256 KiB with a non-SQS/Firehose/Lambda subscription "
        f"present must be refused InvalidParameter, got {code!r}: {message!r}"
    )
    expected_message = (
        "Invalid parameter: MaximumMessageSize greater than 262144 bytes is not supported for "
        "the following protocol: [email]"
    )
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )
    still = sns.get_topic_attributes(TopicArn=ineligible_arn)["Attributes"]
    assert "MaximumMessageSize" not in still, (
        f"the rejected write must leave MaximumMessageSize unset, got "
        f"{still.get('MaximumMessageSize')!r}"
    )

    eligible_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-sns-maxmsg-elig-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=eligible_arn))
    queue_arn = f"arn:aws:sqs:{ctx.region}:{ctx.account}:{ctx.unique_name('sim2real-behav-sns-maxmsg-q-')}"
    sub_arn = sns.subscribe(TopicArn=eligible_arn, Protocol="sqs", Endpoint=queue_arn)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    sns.set_topic_attributes(
        TopicArn=eligible_arn, AttributeName="MaximumMessageSize", AttributeValue=str(_OVER_256_KIB))
    got = sns.get_topic_attributes(TopicArn=eligible_arn)["Attributes"]
    assert got.get("MaximumMessageSize") == str(_OVER_256_KIB), (
        f"the identical value must be accepted once every subscription is SQS; expected "
        f"{_OVER_256_KIB}, got {got.get('MaximumMessageSize')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
