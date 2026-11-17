"""get-subscription-attributes-malformed-id-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-subscription-attributes-malformed-id-rejected"
GROUP = "subscription-lifecycle"
SERVICES = ["sns"]


def _error(fn):
    """(Code, Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _fake_queue_arn(topic_arn: str) -> str:
    """A well-formed SQS queue ARN in the topic's account/region; sqs-protocol Subscribe confirms
    without checking the queue exists, so no SQS resource is needed."""
    parts = topic_arn.split(":")
    return f"arn:aws:sqs:{parts[3]}:{parts[4]}:sim2real-behav-sns-q-{uuid.uuid4().hex[:8]}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetSubscriptionAttributes with a SubscriptionArn that is not ARN-shaped at all is rejected
    with InvalidParameter, distinct from the NotFound a well-formed but absent ARN draws, and the
    real subscription is unaffected.
    """
    sns = ctx.client("sns")
    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-getsubattr-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    sub_arn = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", Endpoint=_fake_queue_arn(topic_arn)
    )["SubscriptionArn"]
    assert sub_arn and sub_arn != "pending confirmation", (
        f"expected an auto-confirmed sqs SubscriptionArn, got {sub_arn!r}"
    )
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    # Positive control: the real subscription's attributes read back fine.
    control = sns.get_subscription_attributes(SubscriptionArn=sub_arn)["Attributes"]
    assert control.get("SubscriptionArn") == sub_arn, (
        f"positive control: expected SubscriptionArn {sub_arn!r} in the attributes, got {control!r}"
    )

    # Break: the identifier is well-typed (a non-empty string) but carries none of an ARN's
    # colon-separated structure, so SNS cannot even parse it into a subscription id.
    code, message = _error(lambda: sns.get_subscription_attributes(SubscriptionArn="not-an-arn"))
    assert code == "InvalidParameter", (
        f"expected InvalidParameter for a non-ARN SubscriptionArn, got {code!r}"
    )
    assert message == (
        "Invalid parameter: SubscriptionArn Reason: An ARN must have at least 6 elements, not 1"
    ), f"unexpected message for a non-ARN SubscriptionArn: {message!r}"

    # The real subscription survives the rejected call untouched.
    after = sns.get_subscription_attributes(SubscriptionArn=sub_arn)["Attributes"]
    assert after.get("SubscriptionArn") == sub_arn, (
        f"expected the real subscription's attributes unchanged after the rejected call, got {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
