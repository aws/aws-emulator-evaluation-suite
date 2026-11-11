"""publish-batch-success-delivery."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "publish-batch-success-delivery"
GROUP = 'publish-batch'
SERVICES = ['sns']


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_sqs_queue_for_sns(ctx, name_prefix="sqs-target-", fifo=False):
    """Create an SQS queue with a policy allowing SNS to deliver to it.

    Returns (queue_url, queue_arn).
    """
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-" + name_prefix)
    attrs = {}
    if fifo:
        if not name.endswith(".fifo"):
            name += ".fifo"
        attrs["FifoQueue"] = "true"
    queue_url = sqs.create_queue(QueueName=name, Attributes=attrs)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    sqs.tag_queue(QueueUrl=queue_url, Tags={"sim2real": "publish-batch-success-delivery", "sim2real:managed": "true"})
    arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowSNS",
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": arn,
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    return queue_url, arn


def _drain_queue(ctx, queue_url, max_messages=10, wait_time=2, delete=True):
    """Receive up to max_messages from a queue in a single poll call.

    Received messages are deleted by default. This matters for FIFO queues: a
    message group is locked while one of its messages is in flight, so an
    ordering test that does not delete would only ever see the first message.
    """
    sqs = ctx.client("sqs")
    resp = sqs.receive_message(
        QueueUrl=queue_url,
        MaxNumberOfMessages=max_messages,
        WaitTimeSeconds=wait_time,
        MessageAttributeNames=["All"],
    )
    messages = resp.get("Messages", [])
    if delete and messages:
        sqs.delete_message_batch(
            QueueUrl=queue_url,
            Entries=[
                {"Id": str(i), "ReceiptHandle": m["ReceiptHandle"]}
                for i, m in enumerate(messages)
            ],
        )
    return messages


def _poll_queue_for_messages(ctx, queue_url, min_count=1, timeout_s=60, interval_s=2):
    """Poll a queue, accumulating (and deleting) messages, until min_count arrive."""
    collected = []

    def probe():
        collected.extend(_drain_queue(ctx, queue_url))
        return collected

    _poll_until(
        probe, lambda c: len(c) >= min_count, timeout_s=timeout_s, interval_s=interval_s
    )
    return collected


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """PublishBatch reports every entry as Successful and each message is actually delivered."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-topic-batch-")
    arn = sns.create_topic(
        Name=name,
        Tags=[
            {"Key": "sim2real", "Value": "publish-batch-success-delivery"},
            {"Key": "sim2real:managed", "Value": "true"},
        ],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    queue_url, queue_arn = _create_sqs_queue_for_sns(ctx, "batch-q-")
    sub_arn = sns.subscribe(
        TopicArn=arn,
        Protocol="sqs",
        Endpoint=queue_arn,
        Attributes={"RawMessageDelivery": "true"},
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    entries = [{"Id": str(i), "Message": f"batch-msg-{i}-{uuid.uuid4()}"} for i in range(3)]
    resp = sns.publish_batch(TopicArn=arn, PublishBatchRequestEntries=entries)
    successful_ids = {e["Id"] for e in resp.get("Successful", [])}
    assert successful_ids == {e["Id"] for e in entries}, (
        f"expected every entry id in Successful, got {resp.get('Successful')}"
    )
    assert not resp.get("Failed"), f"expected no Failed entries, got {resp.get('Failed')}"

    messages = _poll_queue_for_messages(ctx, queue_url, min_count=3, timeout_s=30, interval_s=2)
    bodies = {m["Body"] for m in messages}
    for e in entries:
        assert e["Message"] in bodies, f"missing batch message {e['Message']!r} in delivered set {bodies}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
