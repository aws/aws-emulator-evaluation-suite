"""subscribe-raw-message-delivery-end-to-end."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "subscribe-raw-message-delivery-end-to-end"
GROUP = 'subscription-lifecycle'
SERVICES = ['sns']

_SCENARIO = "sns-raw-delivery-e2e"

def _tags_kv():
    return [{"Key": "sim2real", "Value": _SCENARIO}, {"Key": "sim2real:managed", "Value": "true"}]

def _create_topic(client, ctx, name, attributes=None, tags=None):
    """CreateTopic + register best-effort DeleteTopic cleanup; returns the TopicArn."""
    kwargs = {"Name": name, "Tags": tags if tags is not None else _tags_kv()}
    if attributes:
        kwargs["Attributes"] = attributes
    arn = client.create_topic(**kwargs)["TopicArn"]
    ctx.on_cleanup(lambda: client.delete_topic(TopicArn=arn))
    return arn

def _create_sqs_queue_for_sns(ctx, topic_arn, fifo=False):
    """Create a REAL SQS queue whose policy lets the topic publish to it; returns (queue_url, queue_arn)."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sns-q-")
    attributes = {}
    if fifo:
        name = name + ".fifo"
        attributes["FifoQueue"] = "true"
    queue_url = sqs.create_queue(
        QueueName=name, Attributes=attributes,
        tags={"sim2real": _SCENARIO, "sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda u=queue_url: ctx.client("sqs").delete_queue(QueueUrl=u))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    return queue_url, queue_arn

def _poll_queue_for_messages(ctx, queue_url, min_count=1, timeout_s=60, interval_s=2):
    """Long-poll an SQS queue until min_count messages are collected (or timeout); deletes as it drains."""
    sqs = ctx.client("sqs")
    collected = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and len(collected) < min_count:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=int(interval_s))
        msgs = resp.get("Messages", [])
        for m in msgs:
            collected.append(m)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
        if not msgs:
            time.sleep(interval_s)
    return collected

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A RawMessageDelivery=true SQS subscription receives the published message body verbatim,
    with no SNS JSON envelope, as read from the destination queue.
    """
    sns = ctx.client("sns")
    topic_arn = _create_topic(sns, ctx, ctx.unique_name("sim2real-behav-sns-raw-"))
    queue_url, queue_arn = _create_sqs_queue_for_sns(ctx, topic_arn)

    sub_arn = sns.subscribe(
        TopicArn=topic_arn,
        Protocol="sqs",
        Endpoint=queue_arn,
        Attributes={"RawMessageDelivery": "true"},
    )["SubscriptionArn"]
    if sub_arn and sub_arn != "pending confirmation":
        ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))
    assert sub_arn.startswith(topic_arn + ":"), f"expected an auto-confirmed SubscriptionArn, got {sub_arn!r}"

    payload = f"payload-{uuid.uuid4()}"
    resp = sns.publish(TopicArn=topic_arn, Message=payload)
    assert resp.get("MessageId"), f"Publish must return a MessageId, got {resp}"

    messages = _poll_queue_for_messages(ctx, queue_url, min_count=1, timeout_s=60, interval_s=2)
    bodies = [m["Body"] for m in messages]
    assert payload in bodies, f"expected raw message body {payload!r} in delivered messages {bodies}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
