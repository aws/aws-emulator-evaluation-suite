"""publish-binary-message-attribute-byte-preserved."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "publish-binary-message-attribute-byte-preserved"
GROUP = "server-side"
SERVICES = ["sns"]

_SCENARIO = "sns-binary-attr-raw-delivery"
_TAGS_KV = [{"Key": "sim2real", "Value": _SCENARIO}, {"Key": "sim2real:managed", "Value": "true"}]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Binary message attribute holding every byte 0x00-0xff reaches a raw-delivery SQS
    subscriber as a native Binary SQS attribute, byte-for-byte unchanged."""
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-binattr-topic-"), Tags=_TAGS_KV
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-binattr-q-"),
        tags={"sim2real": _SCENARIO, "sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})

    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))
    sns.set_subscription_attributes(SubscriptionArn=sub_arn, AttributeName="RawMessageDelivery", AttributeValue="true")

    payload = bytes(range(256))
    body_token = ctx.unique_name("sim2real-binattr-body-")
    sns.publish(
        TopicArn=topic_arn,
        Message=body_token,
        MessageAttributes={"payload": {"DataType": "Binary", "BinaryValue": payload}},
    )

    msg = _poll_for_body(ctx, queue_url, body_token, timeout_s=30.0)
    received_attr = msg["MessageAttributes"]["payload"]
    received_bytes = received_attr["BinaryValue"]
    assert bytes(received_bytes) == payload, f"binary attribute corrupted: {received_bytes!r} != {payload!r}"
    assert received_attr["DataType"] == "Binary", (
        f"binary attribute lost its type over raw delivery: {received_attr['DataType']!r}"
    )


def _poll_for_body(ctx, queue_url: str, body_token: str, timeout_s: float = 30.0) -> dict:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            MessageAttributeNames=["All"],
            WaitTimeSeconds=5,
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if msg["Body"] == body_token:
                return msg
    raise AssertionError(f"message {body_token!r} never arrived")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
