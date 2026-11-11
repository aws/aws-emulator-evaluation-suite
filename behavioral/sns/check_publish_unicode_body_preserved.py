"""publish-unicode-body-preserved."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "publish-unicode-body-preserved"
GROUP = "server-side"
SERVICES = ["sns"]

_SCENARIO = "sns-unicode-body"


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": _SCENARIO}, {"Key": "sim2real:managed", "Value": "true"}]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A message body containing unicode and emoji characters is delivered to
    the subscriber unchanged, byte-for-byte."""
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-unicode-topic-"), Tags=_tags_kv()
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-unicode-q-"),
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

    unique_tag = ctx.unique_name("sim2real-unicode-")
    body = f"{unique_tag} \u65e5\u672c\u8a9e \U0001F680 caf\u00e9 \u00e9l\u00e8ve \u4e2d\u6587\u6d4b\u8bd5"

    sns.publish(TopicArn=topic_arn, Message=body)

    received = _poll_for_body_containing(ctx, queue_url, unique_tag, timeout_s=30.0)
    assert received == body, f"unicode body corrupted: {received!r} != {body!r}"


def _poll_for_body_containing(ctx, queue_url: str, needle: str, timeout_s: float = 30.0) -> str:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if needle in msg["Body"]:
                return msg["Body"]
    raise AssertionError(f"message containing {needle!r} never arrived")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
