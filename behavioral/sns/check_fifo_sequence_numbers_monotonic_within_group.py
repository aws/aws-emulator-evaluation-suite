"""fifo-sequence-numbers-monotonic-within-group."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "fifo-sequence-numbers-monotonic-within-group"
GROUP = 'fifo-topic'
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

def _create_fifo_queue_for_sns(ctx, topic_arn):
    """Create a REAL FIFO SQS queue whose policy lets the topic publish to it; returns (queue_url, queue_arn)."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sns-fifoord-q-") + ".fifo"
    queue_url = sqs.create_queue(
        QueueName=name,
        Attributes={"FifoQueue": "true"},
        tags={"sim2real-check": CHECK},
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

def _subscribe_queue(client, ctx, topic_arn, queue_arn):
    """Subscribe an sqs-protocol endpoint (non-raw, so the JSON envelope carries SequenceNumber); register unsubscribe cleanup."""
    sub_arn = client.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)["SubscriptionArn"]
    if sub_arn and sub_arn != "pending confirmation":
        ctx.on_cleanup(lambda: client.unsubscribe(SubscriptionArn=sub_arn))
    return sub_arn

def _poll_queue_for_messages(ctx, queue_url, min_count, timeout_s=90, interval_s=2):
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
    """Publishes to one MessageGroupId on a FIFO topic get strictly increasing SequenceNumbers, and
    a real subscribed queue independently observes delivery preserve both that order and those
    SequenceNumbers.
    """
    sns = ctx.client("sns")
    topic_name = ctx.unique_name("sim2real-behav-sns-fifoord-") + ".fifo"
    topic_arn = _create_topic(
        sns, ctx, topic_name, attributes={"FifoTopic": "true"},
        tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    queue_url, queue_arn = _create_fifo_queue_for_sns(ctx, topic_arn)
    _subscribe_queue(sns, ctx, topic_arn, queue_arn)

    seqs = []
    bodies = []
    for i in range(5):
        body = f"seq-{i}-{uuid.uuid4().hex[:8]}"
        resp = sns.publish(
            TopicArn=topic_arn,
            Message=body,
            MessageGroupId="group-a",
            MessageDeduplicationId=ctx.unique_name(f"sim2real-behav-ord-{i}-"),
        )
        seq = resp.get("SequenceNumber")
        assert seq, f"expected SequenceNumber on FIFO publish #{i}, got {resp}"
        seqs.append(int(seq))
        bodies.append(body)
    assert all(seqs[i] < seqs[i + 1] for i in range(len(seqs) - 1)), (
        f"expected strictly increasing SequenceNumbers within a message group, got {seqs}"
    )

    messages = _poll_queue_for_messages(ctx, queue_url, min_count=5, timeout_s=90, interval_s=2)
    assert len(messages) == 5, f"expected 5 messages delivered to the subscribed queue, got {len(messages)}"
    envelopes = [json.loads(m["Body"]) for m in messages]
    received_bodies = [e.get("Message") for e in envelopes]
    assert received_bodies == bodies, (
        f"expected FIFO delivery to preserve publish order within the group, sent {bodies}, got {received_bodies}"
    )
    received_seqs = [int(e["SequenceNumber"]) for e in envelopes]
    assert received_seqs == seqs, (
        f"expected the delivered envelope's SequenceNumber to match the publish response in order, "
        f"sent {seqs}, got {received_seqs}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
