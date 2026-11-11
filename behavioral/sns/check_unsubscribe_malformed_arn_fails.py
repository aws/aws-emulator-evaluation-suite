"""unsubscribe-malformed-arn-fails."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unsubscribe-malformed-arn-fails"
GROUP = 'subscription-lifecycle'
SERVICES = ['sns']



def _client_error(fn):
    """Call fn() and return its botocore Error dict; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def _fake_queue_arn(topic_arn):
    """A well-formed SQS queue ARN in the topic's account/region (SNS confirms sqs subs
    without verifying the queue exists)."""
    parts = topic_arn.split(":")
    name = f"sim2real-behav-sns-q-{uuid.uuid4().hex[:8]}"
    return f"arn:aws:sqs:{parts[3]}:{parts[4]}:{name}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Unsubscribe with a malformed SubscriptionArn is rejected, the real subscription survives the
    rejected call, and unsubscribing it with its actual ARN still succeeds.
    """
    sns = ctx.client("sns")
    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-unsubbad-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    queue_arn = _fake_queue_arn(topic_arn)
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)["SubscriptionArn"]
    assert sub_arn and sub_arn != "pending confirmation", (
        f"expected the sqs subscription to auto-confirm, got {sub_arn!r}"
    )
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    error = _client_error(lambda: sns.unsubscribe(SubscriptionArn="not-an-arn"))
    assert error.get("Code") == "InvalidParameter", (
        f"expected InvalidParameter for a malformed SubscriptionArn, got {error.get('Code')!r}"
    )
    assert error.get("Message") == "Invalid parameter: SubscriptionArn Reason: An ARN must have at least 6 elements, not 1", (
        f"unexpected refusal message for a malformed SubscriptionArn: {error.get('Message')!r}"
    )

    attrs = sns.get_subscription_attributes(SubscriptionArn=sub_arn)["Attributes"]
    assert attrs.get("SubscriptionArn") == sub_arn, (
        f"the real subscription must survive the rejected malformed-ARN call, "
        f"got attributes {attrs!r}"
    )

    sns.unsubscribe(SubscriptionArn=sub_arn)
    gone = _client_error(lambda: sns.get_subscription_attributes(SubscriptionArn=sub_arn))
    assert gone.get("Code") == "NotFound", (
        f"expected NotFound reading the real subscription after unsubscribing it, got {gone.get('Code')!r}"
    )
    assert gone.get("Message") == "Subscription does not exist", (
        f"unexpected NotFound message reading the unsubscribed subscription: {gone.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
