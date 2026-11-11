"""subscription-raw-message-delivery-attribute."""
from __future__ import annotations

import json
import uuid

from behavioral_harness import tags

CHECK = "subscription-raw-message-delivery-attribute"
GROUP = 'subscription-lifecycle'
SERVICES = ['sns']

def _create_topic(client, ctx, name, attributes=None, tags=None):
    """CreateTopic + register best-effort DeleteTopic cleanup; returns the TopicArn."""
    kwargs = {"Name": name}
    if attributes:
        kwargs["Attributes"] = attributes
    if tags:
        kwargs["Tags"] = tags
    arn = client.create_topic(**kwargs)["TopicArn"]
    ctx.on_cleanup(lambda: client.delete_topic(TopicArn=arn))
    return arn

def _fake_queue_arn(topic_arn, name=None):
    """A well-formed SQS queue ARN in the topic's account/region (SNS confirms sqs subs without verifying the queue exists)."""
    parts = topic_arn.split(":")
    name = name or f"sim2real-behav-sns-q-{uuid.uuid4().hex[:8]}"
    return f"arn:aws:sqs:{parts[3]}:{parts[4]}:{name}"

def _subscribe_fake_queue(client, ctx, topic_arn, queue_arn=None, raw_message_delivery=False,
                          filter_policy=None, filter_policy_scope=None):
    """Subscribe an sqs-protocol endpoint; register unsubscribe cleanup; return the SubscriptionArn."""
    if queue_arn is None:
        queue_arn = _fake_queue_arn(topic_arn)
    attributes = {}
    if raw_message_delivery:
        attributes["RawMessageDelivery"] = "true"
    if filter_policy is not None:
        attributes["FilterPolicy"] = json.dumps(filter_policy)
    if filter_policy_scope is not None:
        attributes["FilterPolicyScope"] = filter_policy_scope
    kwargs = {"TopicArn": topic_arn, "Protocol": "sqs", "Endpoint": queue_arn}
    if attributes:
        kwargs["Attributes"] = attributes
    sub_arn = client.subscribe(**kwargs)["SubscriptionArn"]
    if sub_arn and sub_arn != "pending confirmation":
        ctx.on_cleanup(lambda: client.unsubscribe(SubscriptionArn=sub_arn))
    return sub_arn

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RawMessageDelivery defaults to false and round-trips through SetSubscriptionAttributes."""
    ev = ctx.client("sns")
    topic_arn = _create_topic(
        ev, ctx, ctx.unique_name("sim2real-behav-sns-raw-"),
        tags=[{"Key": "sim2real:managed", "Value": "true"},
              {"Key": "sim2real:prefix", "Value": "sim2real-behav-sns-raw"}],
    )
    sub_arn = _subscribe_fake_queue(ev, ctx, topic_arn)
    assert ev.get_subscription_attributes(SubscriptionArn=sub_arn)["Attributes"].get("RawMessageDelivery") == "false", (
        "expected RawMessageDelivery to default to false"
    )
    ev.set_subscription_attributes(
        SubscriptionArn=sub_arn, AttributeName="RawMessageDelivery", AttributeValue="true"
    )
    after_set = ev.get_subscription_attributes(SubscriptionArn=sub_arn)["Attributes"].get("RawMessageDelivery")
    assert after_set == "true", f"expected RawMessageDelivery=true after set, got {after_set}"
    ev.set_subscription_attributes(
        SubscriptionArn=sub_arn, AttributeName="RawMessageDelivery", AttributeValue="false"
    )
    assert ev.get_subscription_attributes(SubscriptionArn=sub_arn)["Attributes"].get("RawMessageDelivery") == "false", (
        "expected RawMessageDelivery to flip back to false"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
