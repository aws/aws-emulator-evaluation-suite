"""subscription-delivery-policy-reads-back-normalized-on-an-sqs-subscription."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "subscription-delivery-policy-reads-back-normalized-on-an-sqs-subscription"
GROUP = "subscriptions"
SERVICES = ["sns"]

_SENT = {"healthyRetryPolicy": {"numRetries": 5, "minDelayTarget": 1, "maxDelayTarget": 10}}
_STORED = {
    "healthyRetryPolicy": {
        "minDelayTarget": 1, "maxDelayTarget": 10, "numRetries": 5, "numMaxDelayRetries": None,
        "numNoDelayRetries": None, "numMinDelayRetries": None, "backoffFunction": None,
    },
    "sicklyRetryPolicy": None,
    "throttlePolicy": None,
    "requestPolicy": None,
    "guaranteed": False,
}


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A subscription DeliveryPolicy set on an SQS subscription is stored in SNS's normalized form:
    every retry field present (unset ones null), the other policy sections null and guaranteed
    false; a later RawMessageDelivery change keeps the stored policy."""
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    topic = sns.create_topic(Name=ctx.unique_name("sim2real-behav-t-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic))
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    sub = sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=queue_arn,
                        ReturnSubscriptionArn=True)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub))

    sns.set_subscription_attributes(
        SubscriptionArn=sub, AttributeName="DeliveryPolicy", AttributeValue=json.dumps(_SENT)
    )
    attrs = sns.get_subscription_attributes(SubscriptionArn=sub)["Attributes"]
    stored = json.loads(attrs.get("DeliveryPolicy", "null"))
    assert stored == _STORED, f"the stored DeliveryPolicy is {stored!r}, expected {_STORED!r}"
    assert attrs.get("Protocol") == "sqs", f"subscription protocol {attrs.get('Protocol')!r}"

    sns.set_subscription_attributes(
        SubscriptionArn=sub, AttributeName="RawMessageDelivery", AttributeValue="true"
    )
    attrs = sns.get_subscription_attributes(SubscriptionArn=sub)["Attributes"]
    assert attrs.get("RawMessageDelivery") == "true", f"RawMessageDelivery not stored: {attrs!r}"
    assert json.loads(attrs.get("DeliveryPolicy", "null")) == _STORED, (
        f"a RawMessageDelivery change altered the DeliveryPolicy: {attrs.get('DeliveryPolicy')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
