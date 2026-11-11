"""unsubscribe-removes-subscription."""
from __future__ import annotations

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unsubscribe-removes-subscription"
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

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Unsubscribe deletes the subscription: GetSubscriptionAttributes afterward returns NotFound,
    the dead ARN no longer appears in the topic's subscription list, and a further mutation on that
    same ARN (SetSubscriptionAttributes) is rejected too — not just the read."""
    ev = ctx.client("sns")
    topic_arn = _create_topic(
        ev, ctx, ctx.unique_name("sim2real-behav-sns-unsub-"),
        tags=[{"Key": "sim2real", "Value": "sns-unsubscribe"},
              {"Key": "sim2real:managed", "Value": "true"}],
    )
    sub_arn = _subscribe_fake_queue(ev, ctx, topic_arn)
    ev.unsubscribe(SubscriptionArn=sub_arn)

    try:
        result = ev.get_subscription_attributes(SubscriptionArn=sub_arn)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(f"GetSubscriptionAttributes after unsubscribe SUCCEEDED: {result!r}")
    assert code == "NotFound", f"expected NotFound after unsubscribe, got {code}"
    assert message == "Subscription does not exist", f"unexpected NotFound message after unsubscribe: {message!r}"

    remaining = [s["SubscriptionArn"]
                 for s in ev.list_subscriptions_by_topic(TopicArn=topic_arn)["Subscriptions"]]
    assert sub_arn not in remaining, (
        f"unsubscribed ARN {sub_arn!r} is still listed on the topic: {remaining!r}"
    )

    try:
        result = ev.set_subscription_attributes(
            SubscriptionArn=sub_arn, AttributeName="RawMessageDelivery", AttributeValue="true"
        )
    except ClientError as exc:
        set_code = exc.response.get("Error", {}).get("Code")
        set_message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(f"SetSubscriptionAttributes on the removed ARN SUCCEEDED: {result!r}")
    assert set_code == "NotFound", (
        f"expected SetSubscriptionAttributes on the removed ARN to be rejected, got {set_code}"
    )
    assert set_message == "Subscription does not exist", (
        f"unexpected NotFound message for SetSubscriptionAttributes on the removed ARN: {set_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
