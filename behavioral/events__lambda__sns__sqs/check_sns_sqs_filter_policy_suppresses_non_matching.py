"""sns-sqs-filter-policy-suppresses-non-matching."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "sns-sqs-filter-policy-suppresses-non-matching"

GROUP = "event-propagation"

SERVICES = ["events", "lambda", "sns", "sqs"]


@tags(
    "axis:negative-delivery",
    "cap:c7",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """SNS filter policies deliver only matching messages to a subscribed SQS queue."""
    topic = _create_topic(ctx)
    queue = _create_queue(ctx)
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue["arn"],
                "Condition": {"ArnEquals": {"aws:SourceArn": topic["arn"]}},
            }
        ],
    }
    sqs.set_queue_attributes(
        QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)}
    )
    sub = sns.subscribe(
        TopicArn=topic["arn"],
        Protocol="sqs",
        Endpoint=queue["arn"],
        Attributes={"FilterPolicy": json.dumps({"category": ["orders"]})},
    )
    ctx.on_cleanup(
        lambda: ctx.client("sns").unsubscribe(SubscriptionArn=sub["SubscriptionArn"])
    )

    # Non-matching publish first — must be suppressed.
    sns.publish(
        TopicArn=topic["arn"],
        Message="should-be-filtered",
        MessageAttributes={
            "category": {"DataType": "String", "StringValue": "invoices"}
        },
    )
    # Matching publish — must arrive.
    start = time.monotonic()
    sns.publish(
        TopicArn=topic["arn"],
        Message="should-arrive",
        MessageAttributes={"category": {"DataType": "String", "StringValue": "orders"}},
    )

    msgs = _wait_for_messages(ctx, queue["url"], expected_count=1, timeout_s=60)
    matching_latency_s = time.monotonic() - start
    assert len(msgs) == 1, (
        "expected exactly one matching message to pass the filter policy"
    )
    body = msgs[0]["body"]
    assert body["Message"] == "should-arrive", (
        f"expected the matching message body, got {body!r}"
    )

    # Absence bound: a poll that only ever requests `expected_count` messages can never notice a
    # second, non-matching message sitting behind the one it collected. Hold the queue open for a
    # window calibrated to the positive control's own delivery latency, and confirm emptiness on an
    # independent side-channel (ApproximateNumberOfMessages) too.
    absence_window_s = max(20.0, matching_latency_s * 3)
    leaked = _drain_for_leaks(ctx, queue["url"], absence_window_s)
    assert leaked == [], (
        f"filter policy leaked the suppressed message onto the queue: {leaked!r}"
    )
    remaining = sqs.get_queue_attributes(
        QueueUrl=queue["url"], AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]["ApproximateNumberOfMessages"]
    assert remaining == "0", (
        f"expected the queue empty after the drain, got ApproximateNumberOfMessages={remaining!r}"
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


def _drain_for_leaks(ctx, queue_url, window_s):
    """Poll queue_url for window_s; return any message bodies seen (deletes as it drains)."""
    sqs = ctx.client("sqs")
    leaked: list[Any] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        remaining = max(1, int(deadline - time.monotonic()))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=min(5, remaining),
        )
        for msg in resp.get("Messages", []):
            leaked.append(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return leaked


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
