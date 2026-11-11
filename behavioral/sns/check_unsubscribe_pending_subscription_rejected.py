"""unsubscribe-pending-subscription-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unsubscribe-pending-subscription-rejected"
GROUP = 'subscription-lifecycle'
SERVICES = ['sns']


def _error(fn):
    """Return (Error.Code, Error.Message) of the ClientError fn raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Unsubscribe on a pending email subscription's real ARN is refused and it stays pending, while
    Unsubscribe on a confirmed sqs subscription of the same topic succeeds and removes it.
    """
    sns = ctx.client("sns")
    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-sns-unsubpend-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TopicArn"]
    # A pending subscription cannot be unsubscribed; DeleteTopic removes it with the topic.
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    region, account = topic_arn.split(":")[3:5]

    pending = sns.subscribe(
        TopicArn=topic_arn, Protocol="email", ReturnSubscriptionArn=True,
        Endpoint=f"{ctx.unique_name('sim2real-behav-sns')}@example.com",
    )["SubscriptionArn"]
    confirmed = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", ReturnSubscriptionArn=True,
        Endpoint=f"arn:aws:sqs:{region}:{account}:{ctx.unique_name('sim2real-behav-sns-unsubpend-q-')}",
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=confirmed))

    code, message = _error(lambda: sns.unsubscribe(SubscriptionArn=pending))
    assert code == "InvalidParameter", f"Unsubscribe on a pending subscription gave {code!r}"
    assert message == ("Invalid parameter: SubscriptionArn Reason: Cannot unsubscribe a "
                       "subscription that is pending confirmation"), (
        f"unexpected message for Unsubscribe on a pending subscription: {message!r}"
    )
    state = sns.get_subscription_attributes(SubscriptionArn=pending)["Attributes"]
    assert state.get("PendingConfirmation") == "true", (
        f"the refused Unsubscribe must leave the subscription pending, got {state.get('PendingConfirmation')!r}"
    )

    sns.unsubscribe(SubscriptionArn=confirmed)
    code, message = _error(lambda: sns.get_subscription_attributes(SubscriptionArn=confirmed))
    assert code == "NotFound", f"the unsubscribed confirmed subscription must be gone, got {code!r}"
    assert message == "Subscription does not exist", f"unexpected NotFound message: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
