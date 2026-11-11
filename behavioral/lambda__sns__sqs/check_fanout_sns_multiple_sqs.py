"""fanout-sns-multiple-sqs."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "fanout-sns-multiple-sqs"

GROUP = "event-propagation"

SERVICES = ["lambda", "sns", "sqs"]


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A single SNS publish fans out to all subscribed SQS queues."""
    topic = _create_topic(ctx)
    queues = [_create_queue(ctx) for _ in range(3)]
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")
    for q in queues:
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "sns.amazonaws.com"},
                    "Action": "sqs:SendMessage",
                    "Resource": q["arn"],
                    "Condition": {"ArnEquals": {"aws:SourceArn": topic["arn"]}},
                }
            ],
        }
        sqs.set_queue_attributes(
            QueueUrl=q["url"], Attributes={"Policy": json.dumps(policy)}
        )
        sub = sns.subscribe(TopicArn=topic["arn"], Protocol="sqs", Endpoint=q["arn"])
        ctx.on_cleanup(
            lambda arn=sub["SubscriptionArn"]: ctx.client("sns").unsubscribe(
                SubscriptionArn=arn
            )
        )
    sns.publish(TopicArn=topic["arn"], Message="fanout-message")
    for q in queues:
        messages = _wait_for_messages(ctx, q["url"], expected_count=1, timeout_s=60)
        assert len(messages) == 1, (
            f"Queue {q['name']} did not receive the fanned-out message"
        )
        # Default (non-raw) SNS->SQS delivery wraps the payload in an SNS envelope;
        # wait_for_messages JSON-parses the body, so it arrives as a dict.
        envelope = messages[0]["body"]
        assert isinstance(envelope, dict), (
            f"Queue {q['name']}: expected SNS envelope dict, got {type(envelope)}: {envelope}"
        )
        assert envelope["Type"] == "Notification", (
            f"Queue {q['name']}: expected Type 'Notification', got {envelope.get('Type')!r}"
        )
        assert envelope["Message"] == "fanout-message", (
            f"Queue {q['name']}: expected Message 'fanout-message', got {envelope.get('Message')!r}"
        )
        assert envelope["TopicArn"] == topic["arn"], (
            f"Queue {q['name']}: expected TopicArn {topic['arn']!r}, got {envelope.get('TopicArn')!r}"
        )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _create_queue(ctx, fifo: bool = False, **attrs: str) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    base = _xname(ctx, "q")
    name = f"{base}.fifo" if fifo else base
    sqs = ctx.client("sqs")
    create_attrs = dict(attrs)
    if fifo:
        create_attrs["FifoQueue"] = "true"
    resp = sqs.create_queue(
        QueueName=name, Attributes=create_attrs, tags=_xsvc_resource_tags()
    )
    url = resp["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"name": name, "url": url, "arn": arn}


def _create_topic(ctx) -> dict[str, str]:
    """Create an SNS topic (registers delete_topic teardown). Returns {name,arn}."""
    name = _xname(ctx, "topic")
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=name, Tags=_xsvc_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return {"name": name, "arn": arn}


def _wait_for_messages(ctx, queue_url, expected_count=1, timeout_s=60.0, delete=True):
    """Poll SQS until expected_count messages arrive; return them (raises on timeout)."""
    sqs = ctx.client("sqs")
    messages: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while len(messages) < expected_count and time.monotonic() < deadline:
        remaining = max(1, int(deadline - time.monotonic()))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=min(10, expected_count - len(messages)),
            WaitTimeSeconds=min(5, remaining),
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            messages.append(
                {
                    "body": body,
                    "message_id": msg["MessageId"],
                    "receipt_handle": msg["ReceiptHandle"],
                    "attributes": msg.get("MessageAttributes", {}),
                }
            )
            if delete:
                sqs.delete_message(
                    QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"]
                )
    if len(messages) < expected_count:
        raise AssertionError(
            f"Expected {expected_count} messages, got {len(messages)} within {timeout_s}s"
        )
    return messages


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
