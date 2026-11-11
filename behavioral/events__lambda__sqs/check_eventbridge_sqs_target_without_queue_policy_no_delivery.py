"""eventbridge-sqs-target-without-queue-policy-no-delivery."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-sqs-target-without-queue-policy-no-delivery"

GROUP = "overly-permissive"

SERVICES = ["events", "lambda", "sqs"]


@tags("axis:negative-delivery", "cap:c1", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Without an SQS queue policy grant, EventBridge must not deliver messages, while an
    identical sibling target on the SAME rule that DOES have the grant receives the event
    (in-file positive control, twin queues fired by the same PutEvents call)."""
    no_policy_queue = _create_queue(ctx)
    with_policy_queue = _create_queue(ctx)
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    rule_name = ctx.unique_name("rule-noqpolicy-")
    rule = events.put_rule(
        Name=rule_name, EventPattern=json.dumps({"source": ["custom.noqpolicy"]})
    )
    ctx.on_cleanup(lambda: ctx.client("events").delete_rule(Name=rule_name))

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridgeSendMessage",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": with_policy_queue["arn"],
                "Condition": {"ArnEquals": {"aws:SourceArn": rule["RuleArn"]}},
            }
        ],
    }
    sqs.set_queue_attributes(
        QueueUrl=with_policy_queue["url"], Attributes={"Policy": json.dumps(policy)}
    )

    # Intentionally skip the queue policy grant for t1; t2 has it (positive control).
    events.put_targets(
        Rule=rule_name,
        Targets=[
            {"Id": "t1", "Arn": no_policy_queue["arn"]},
            {"Id": "t2", "Arn": with_policy_queue["arn"]},
        ],
    )
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(Rule=rule_name, Ids=["t1", "t2"])
    )

    started = time.monotonic()
    events.put_events(
        Entries=[{"Source": "custom.noqpolicy", "DetailType": "Test", "Detail": "{}"}]
    )

    delivered = _wait_for_messages(
        ctx, with_policy_queue["url"], expected_count=1, timeout_s=60
    )
    assert len(delivered) == 1, (
        "positive control failed: the policy-backed sibling target never received the event"
    )
    positive_latency_s = time.monotonic() - started

    # Absence window is calibrated to (>=3x) how long the same wiring took to deliver the
    # positive control in this run, not a fixed guess.
    absence_window_s = max(15.0, positive_latency_s * 3)
    leaked = _drain_for(ctx, no_policy_queue["url"], timeout_s=absence_window_s)
    assert leaked == [], (
        f"SQS must not receive messages without a queue policy grant, got {leaked!r}"
    )

    approx = sqs.get_queue_attributes(
        QueueUrl=no_policy_queue["url"], AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]["ApproximateNumberOfMessages"]
    assert approx == "0", (
        f"queue lacking a policy grant should report ApproximateNumberOfMessages=0, got {approx}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


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


def _drain_for(ctx, queue_url, timeout_s=30.0, delete=True):
    """Poll SQS for up to timeout_s and return whatever messages arrive (empty if none)."""
    sqs = ctx.client("sqs")
    messages: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        remaining = max(1, int(deadline - time.monotonic()))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
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
    return messages


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
