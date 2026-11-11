"""eventbridge-fanout-multiple-sqs-targets."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-fanout-multiple-sqs-targets"

GROUP = "event-propagation"

SERVICES = ["events", "s3", "sqs"]


def _sqs_policy_for_events(queue_arn: str, rule_arn: str | None = None) -> dict:
    statement = {
        "Sid": "AllowEventsSendMessage",
        "Effect": "Allow",
        "Principal": {"Service": "events.amazonaws.com"},
        "Action": "sqs:SendMessage",
        "Resource": queue_arn,
    }
    if rule_arn:
        statement["Condition"] = {"ArnEquals": {"aws:SourceArn": rule_arn}}
    return {"Version": "2012-10-17", "Statement": [statement]}


def _set_queue_policy(ctx, queue_url: str, policy: dict) -> None:
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)}
    )


def _rule_arn(ctx, rule_name: str, bus_name: str | None = None) -> str:
    kwargs = {"Name": rule_name}
    if bus_name:
        kwargs["EventBusName"] = bus_name
    return ctx.client("events").describe_rule(**kwargs)["Arn"]


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
    """A single EventBridge rule with multiple SQS targets delivers to ALL of them."""
    events = ctx.client("events")
    queue_a = _create_queue(ctx)
    queue_b = _create_queue(ctx)

    bus_name = ctx.unique_name("bus-")
    events.create_event_bus(Name=bus_name)
    ctx.on_cleanup(lambda: ctx.client("events").delete_event_bus(Name=bus_name))

    rule_name = ctx.unique_name("rule-fanout-")
    events.put_rule(
        Name=rule_name,
        EventBusName=bus_name,
        EventPattern=json.dumps(
            {"source": ["app.orders"], "detail-type": ["OrderPlaced"]}
        ),
    )
    ctx.on_cleanup(
        lambda: ctx.client("events").delete_rule(Name=rule_name, EventBusName=bus_name)
    )
    rule_arn = _rule_arn(ctx, rule_name, bus_name)

    _set_queue_policy(
        ctx, queue_a["url"], _sqs_policy_for_events(queue_a["arn"], rule_arn)
    )
    _set_queue_policy(
        ctx, queue_b["url"], _sqs_policy_for_events(queue_b["arn"], rule_arn)
    )

    events.put_targets(
        Rule=rule_name,
        EventBusName=bus_name,
        Targets=[
            {"Id": "target-a", "Arn": queue_a["arn"]},
            {"Id": "target-b", "Arn": queue_b["arn"]},
        ],
    )
    ctx.on_cleanup(
        lambda: events.remove_targets(
            Rule=rule_name, Ids=["target-a", "target-b"], EventBusName=bus_name
        )
    )

    _entry = {
        "Source": "app.orders",
        "DetailType": "OrderPlaced",
        "Detail": json.dumps({"order_id": "fanout-1"}),
        "EventBusName": bus_name,
    }
    # Re-emit until BOTH targets receive: a freshly-created rule can drop the first PutEvents before
    # the path is live, and EB never retries. Both asserts are truthiness (>=1 each), so re-emitting
    # is safe (unlike an exact-count assertion).
    msgs_a = msgs_b = None
    for _ in range(8):
        events.put_events(Entries=[_entry])
        if not msgs_a:
            msgs_a = _receive_messages(ctx, queue_a["url"], expected_count=1, timeout_s=6)
        if not msgs_b:
            msgs_b = _receive_messages(ctx, queue_b["url"], expected_count=1, timeout_s=6)
        if msgs_a and msgs_b:
            break
    assert msgs_a, "expected fanout target A to receive the event"
    assert msgs_b, "expected fanout target B to receive the event"
    for label, msgs in (("A", msgs_a), ("B", msgs_b)):
        envelope = msgs[0]["body"]
        assert envelope.get("source") == "app.orders", (
            f"target {label}: expected envelope source 'app.orders', got {envelope.get('source')!r}"
        )
        assert envelope.get("detail-type") == "OrderPlaced", (
            f"target {label}: expected envelope detail-type 'OrderPlaced', "
            f"got {envelope.get('detail-type')!r}"
        )
        assert envelope.get("detail", {}).get("order_id") == "fanout-1", (
            f"target {label}: expected detail.order_id 'fanout-1', "
            f"got {envelope.get('detail')!r}"
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


def _receive_messages(ctx, queue_url, expected_count=1, timeout_s=60.0, delete=True):
    """Poll SQS until expected_count messages arrive or timeout_s elapses; return what arrived."""
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
    return messages


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
