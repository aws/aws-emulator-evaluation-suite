"""resubscribe-after-unsubscribe-mints-a-new-arn."""
from __future__ import annotations


from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resubscribe-after-unsubscribe-mints-a-new-arn"
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Re-subscribing a live endpoint returns the same ARN, but subscribing it after Unsubscribe
    mints a new ARN with default attributes while the old ARN stays NotFound.
    """
    sns = ctx.client("sns")
    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-resub-"),
                                 Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    region, account = topic_arn.split(":")[3:5]
    endpoint = f"arn:aws:sqs:{region}:{account}:{ctx.unique_name('sim2real-behav-sns-resub-q-')}"

    first = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=endpoint,
                          Attributes={"RawMessageDelivery": "true"},
                          ReturnSubscriptionArn=True)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=first))
    again = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=endpoint,
                          Attributes={"RawMessageDelivery": "true"},
                          ReturnSubscriptionArn=True)["SubscriptionArn"]
    assert again == first, "re-subscribing a live endpoint must return the existing ARN"

    sns.unsubscribe(SubscriptionArn=first)
    second = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=endpoint,
                           ReturnSubscriptionArn=True)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=second))
    assert second != first, "a subscription created after Unsubscribe must get a new ARN"
    assert second.startswith(topic_arn + ":"), "the new subscription's ARN must sit under its topic"
    attrs = sns.get_subscription_attributes(SubscriptionArn=second)["Attributes"]
    assert attrs.get("RawMessageDelivery") == "false", (
        f"the new subscription must start from defaults, RawMessageDelivery={attrs.get('RawMessageDelivery')!r}"
    )
    code, message = _error(lambda: sns.get_subscription_attributes(SubscriptionArn=first))
    assert code == "NotFound", f"the old subscription ARN must stay gone, got {code!r}"
    assert message == "Subscription does not exist", f"unexpected NotFound message: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
