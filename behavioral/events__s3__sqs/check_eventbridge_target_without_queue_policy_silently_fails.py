"""eventbridge-target-without-queue-policy-silently-fails."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-target-without-queue-policy-silently-fails"

GROUP = "overly-permissive"

SERVICES = ["events", "s3", "sqs"]


def _is_s3_test_event(body: object) -> bool:
    """True for S3's one-off destination-validation handshake message.

    When a queue is first attached as an S3 notification destination, S3 posts
    {"Service":"Amazon S3","Event":"s3:TestEvent", ...} to prove it can write to
    the queue. It carries no "Records" and is NOT an object event, so it must
    never be mistaken for one (nor counted as an over-delivery).
    """
    return isinstance(body, dict) and body.get("Event") == "s3:TestEvent"


def _poll_for_no_messages(
    ctx,
    queue_url: str,
    window_s: float = 45,
    ignore_s3_test_event: bool = True,
) -> list[dict]:
    """Watch a queue for *window_s* and return whatever arrived (expected: nothing).

    _wait_for_messages() raises AssertionError when the expected count never
    arrives, so it cannot express a NEGATIVE expectation. Overly-permissive
    checks need "nothing should ever show up", which is what this returns.
    Exits early as soon as any real message appears so a leak fails fast.
    """
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + window_s
    received: list[dict] = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=5,
            MessageAttributeNames=["All"],
        )
        for m in resp.get("Messages", []):
            try:
                body = json.loads(m["Body"])
            except (json.JSONDecodeError, ValueError):
                body = m["Body"]
            if ignore_s3_test_event and _is_s3_test_event(body):
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
                continue
            received.append({"body": body})
        if received:
            break
    return received


@tags("axis:negative-delivery", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutTargets accepts an SQS target without a queue policy but that queue never receives the
    event, while a policy-granted queue on the same rule receives it with its marker."""
    events = ctx.client("events")
    queue_nopolicy = _create_queue(ctx)  # no policy allowing events.amazonaws.com

    bus_name = ctx.unique_name("bus-")
    events.create_event_bus(Name=bus_name)
    ctx.on_cleanup(lambda: ctx.client("events").delete_event_bus(Name=bus_name))

    rule_name = ctx.unique_name("rule-nopolicy-")
    rule_arn = events.put_rule(
        Name=rule_name,
        EventBusName=bus_name,
        EventPattern=json.dumps(
            {"source": ["app.orders"], "detail-type": ["OrderPlaced"]}
        ),
    )["RuleArn"]
    ctx.on_cleanup(
        lambda: ctx.client("events").delete_rule(Name=rule_name, EventBusName=bus_name)
    )

    queue_withpolicy = _create_queue(ctx)
    _set_queue_policy(
        ctx, queue_withpolicy["url"],
        _sqs_policy_for_events(queue_withpolicy["arn"], rule_arn),
    )

    # PutTargets itself does not validate downstream permissions, it should succeed for both.
    events.put_targets(
        Rule=rule_name,
        EventBusName=bus_name,
        Targets=[
            {"Id": "sqs-target-nopolicy", "Arn": queue_nopolicy["arn"]},
            {"Id": "sqs-target-withpolicy", "Arn": queue_withpolicy["arn"]},
        ],
    )
    ctx.on_cleanup(
        lambda: events.remove_targets(
            Rule=rule_name,
            Ids=["sqs-target-nopolicy", "sqs-target-withpolicy"],
            EventBusName=bus_name,
        )
    )

    marker = ctx.unique_name("marker-")
    send_time = time.monotonic()
    events.put_events(
        Entries=[
            {
                "Source": "app.orders",
                "DetailType": "OrderPlaced",
                "Detail": json.dumps({"order_id": "unauthorized", "marker": marker}),
                "EventBusName": bus_name,
            }
        ]
    )

    delivered = _poll_for_marker(ctx, queue_withpolicy["url"], marker, timeout_s=60.0)
    assert delivered["detail"]["marker"] == marker, (
        "positive-control queue (WITH the resource policy) never received the event -- "
        "cannot attribute the no-policy queue's silence to policy enforcement rather than "
        "a delivery path that never worked in this run"
    )
    positive_latency_s = time.monotonic() - send_time

    hold_s = max(15.0, positive_latency_s * 3)
    messages = _poll_for_no_messages(ctx, queue_nopolicy["url"], window_s=hold_s)
    assert not messages, (
        "queue received a message despite missing resource policy for events.amazonaws.com "
        "-- emulator must not fabricate delivery that AWS would reject"
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


def _sqs_policy_for_events(queue_arn: str, rule_arn: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridgeDelivery",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }


def _set_queue_policy(ctx, queue_url: str, policy: dict) -> None:
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)}
    )


def _poll_for_marker(ctx, queue_url: str, marker: str, timeout_s: float = 60.0) -> dict:
    """Poll until a message whose detail.marker == marker arrives; raise on timeout."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if (
                isinstance(body, dict)
                and isinstance(body.get("detail"), dict)
                and body["detail"].get("marker") == marker
            ):
                return body
    raise AssertionError(
        f"event with marker {marker} was never delivered to {queue_url} within {timeout_s}s"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
