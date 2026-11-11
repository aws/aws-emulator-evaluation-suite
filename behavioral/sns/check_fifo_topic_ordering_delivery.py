"""fifo-topic-ordering-delivery."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "fifo-topic-ordering-delivery"
GROUP = 'fifo-topic'
SERVICES = ['sns']

_SCENARIO = "sns-fifo-ordering"

def _tags_kv():
    return [{"Key": "sim2real", "Value": _SCENARIO}, {"Key": "sim2real:managed", "Value": "true"}]

def _create_topic(client, ctx, name, attributes=None):
    """CreateTopic (tagged) + register best-effort DeleteTopic cleanup; returns the TopicArn."""
    kwargs = {"Name": name, "Tags": _tags_kv()}
    if attributes:
        kwargs["Attributes"] = attributes
    arn = client.create_topic(**kwargs)["TopicArn"]
    ctx.on_cleanup(lambda: client.delete_topic(TopicArn=arn))
    return arn

def _create_sqs_queue_for_sns(ctx, topic_arn, fifo=False):
    """Create a REAL, tagged SQS queue whose policy lets the topic publish to it; returns (queue_url, queue_arn)."""
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

def _poll_queue_for_messages(ctx, queue_url, min_count=1, timeout_s=90, interval_s=2):
    """Long-poll an SQS queue until min_count messages are collected; deletes as it drains; raises on timeout."""
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
    if len(collected) < min_count:
        raise AssertionError(
            f"only {len(collected)}/{min_count} messages arrived within {timeout_s}s: "
            f"{[m.get('Body') for m in collected]!r}"
        )
    return collected

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Messages published to a FIFO topic under one MessageGroupId each return a SequenceNumber
    and arrive at a subscribed FIFO SQS queue in publish order."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-fifo-order-") + ".fifo"
    topic_arn = _create_topic(
        sns, ctx, name, attributes={"FifoTopic": "true", "ContentBasedDeduplication": "true"}
    )
    queue_url, queue_arn = _create_sqs_queue_for_sns(ctx, topic_arn, fifo=True)

    sub_arn = sns.subscribe(
        TopicArn=topic_arn,
        Protocol="sqs",
        Endpoint=queue_arn,
        Attributes={"RawMessageDelivery": "true"},
    )["SubscriptionArn"]
    if sub_arn and sub_arn != "pending confirmation":
        ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    group_id = ctx.unique_name("group-")
    sent = [f"msg-{i}-{uuid.uuid4()}" for i in range(3)]
    for body in sent:
        resp = sns.publish(TopicArn=topic_arn, Message=body, MessageGroupId=group_id)
        assert resp.get("SequenceNumber"), f"a FIFO topic publish must return a SequenceNumber: {resp}"

    messages = _poll_queue_for_messages(ctx, queue_url, min_count=len(sent), timeout_s=90, interval_s=2)
    received = [m["Body"] for m in messages[:len(sent)]]
    assert received == sent, f"expected FIFO delivery order {sent}, got {received}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
