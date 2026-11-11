"""sns-to-sqs-filter-policy."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "sns-to-sqs-filter-policy"

GROUP = "data-format"

SERVICES = ["lambda", "sns", "sqs"]


@tags(
    "axis:negative-delivery",
    "cap:c7",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """SNS filter policies deliver messages only to subscriptions whose filter matches message attributes."""
    topic = _create_topic(ctx)
    queue_match = _create_queue(ctx)
    queue_nomatch = _create_queue(ctx)
    sqs = ctx.client("sqs")
    for q in (queue_match, queue_nomatch):
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
    sns = ctx.client("sns")
    sub1 = sns.subscribe(
        TopicArn=topic["arn"],
        Protocol="sqs",
        Endpoint=queue_match["arn"],
        Attributes={"FilterPolicy": json.dumps({"category": ["orders"]})},
    )
    sub2 = sns.subscribe(
        TopicArn=topic["arn"],
        Protocol="sqs",
        Endpoint=queue_nomatch["arn"],
        Attributes={"FilterPolicy": json.dumps({"category": ["shipping"]})},
    )
    ctx.on_cleanup(
        lambda arn=sub1["SubscriptionArn"]: ctx.client("sns").unsubscribe(
            SubscriptionArn=arn
        )
    )
    ctx.on_cleanup(
        lambda arn=sub2["SubscriptionArn"]: ctx.client("sns").unsubscribe(
            SubscriptionArn=arn
        )
    )
    publish_start = time.monotonic()
    sns.publish(
        TopicArn=topic["arn"],
        Message="order-event",
        MessageAttributes={"category": {"DataType": "String", "StringValue": "orders"}},
    )
    matched = _wait_for_messages(
        ctx, queue_match["url"], expected_count=1, timeout_s=60
    )
    assert len(matched) == 1, (
        f"expected exactly 1 message on the matching-filter queue, got {len(matched)}"
    )

    # Calibrated window: the matching queue's own observed delivery latency, on the same publish, is
    # the yardstick for how long a real non-matching delivery would take to show up.
    match_latency_s = time.monotonic() - publish_start
    absence_deadline = publish_start + max(3 * match_latency_s, 15.0)
    leaked = _confirm_absent(ctx, queue_nomatch["url"], absence_deadline)
    assert not leaked, (
        "message delivered to subscription with a non-matching filter policy: "
        f"{[m['body'] for m in leaked]}"
    )
    attrs = sqs.get_queue_attributes(
        QueueUrl=queue_nomatch["url"], AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]
    assert attrs["ApproximateNumberOfMessages"] == "0", (
        "non-matching queue's own reported depth is not 0 after the calibrated absence "
        f"window: {attrs}"
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


def _confirm_absent(ctx, queue_url, deadline_monotonic):
    """Poll a queue until deadline_monotonic; return any messages seen (deleted as found).

    Never raises on absence — an empty return means nothing arrived in the window.
    """
    sqs = ctx.client("sqs")
    seen: list[dict[str, Any]] = []
    while time.monotonic() < deadline_monotonic:
        remaining = max(1, int(deadline_monotonic - time.monotonic()))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=min(5, remaining),
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            seen.append({"body": msg["Body"], "message_id": msg["MessageId"]})
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return seen


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
