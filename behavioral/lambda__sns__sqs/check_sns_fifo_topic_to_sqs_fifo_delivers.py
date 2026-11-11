"""sns-fifo-topic-to-sqs-fifo-delivers."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "sns-fifo-topic-to-sqs-fifo-delivers"
GROUP = "notification"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Publishing a sequence of messages with the same MessageGroupId to an SNS FIFO topic
    delivers them, in order, to a subscribed SQS FIFO queue."""
    sns = ctx.client("sns")
    ctx.client("sqs")

    topic_arn = _create_fifo_topic(ctx)
    queue_url, queue_arn = _create_fifo_queue(ctx)
    _allow_sns_to_send_to_queue(ctx, queue_url, queue_arn, topic_arn)

    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    group_id = "order-test-group"
    for seq in range(3):
        sns.publish(
            TopicArn=topic_arn,
            Message=json.dumps({"seq": seq}),
            MessageGroupId=group_id,
        )

    received_seqs = _collect_ordered_messages(ctx, queue_url, expected_count=3, timeout_s=60.0)
    assert received_seqs == [0, 1, 2], f"expected in-order [0, 1, 2], got {received_seqs}"


def _create_fifo_topic(ctx) -> str:
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-xsvc-topic-") + ".fifo"
    arn = sns.create_topic(
        Name=name,
        Attributes={"FifoTopic": "true", "ContentBasedDeduplication": "true"},
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


def _create_fifo_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-xsvc-q-") + ".fifo"
    url = sqs.create_queue(
        QueueName=name,
        Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true"},
        tags={"sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _allow_sns_to_send_to_queue(ctx, queue_url: str, queue_arn: str, topic_arn: str) -> None:
    sqs = ctx.client("sqs")
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "SQS:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})


def _collect_ordered_messages(ctx, queue_url: str, expected_count: int, timeout_s: float) -> list[int]:
    sqs = ctx.client("sqs")
    seqs: list[int] = []
    deadline = time.monotonic() + timeout_s
    while len(seqs) < expected_count and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            envelope = json.loads(msg["Body"])
            payload = json.loads(envelope["Message"])
            seqs.append(payload["seq"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    if len(seqs) < expected_count:
        raise AssertionError(f"expected {expected_count} messages, got {len(seqs)} within {timeout_s}s")
    return seqs


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
