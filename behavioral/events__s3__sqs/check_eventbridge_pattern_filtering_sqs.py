"""eventbridge-pattern-filtering-sqs."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-pattern-filtering-sqs"

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


@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """EventBridge rule pattern matching only forwards matching detail-types to SQS."""
    events = ctx.client("events")
    queue = _create_queue(ctx)

    bus_name = ctx.unique_name("bus-")
    events.create_event_bus(Name=bus_name)
    ctx.on_cleanup(lambda: ctx.client("events").delete_event_bus(Name=bus_name))

    rule_name = ctx.unique_name("rule-filter-")
    events.put_rule(
        Name=rule_name,
        EventBusName=bus_name,
        EventPattern=json.dumps(
            {"source": ["app.orders"], "detail-type": ["OrderShipped"]}
        ),
    )
    ctx.on_cleanup(
        lambda: ctx.client("events").delete_rule(Name=rule_name, EventBusName=bus_name)
    )
    rule_arn = _rule_arn(ctx, rule_name, bus_name)

    _set_queue_policy(ctx, queue["url"], _sqs_policy_for_events(queue["arn"], rule_arn))
    events.put_targets(
        Rule=rule_name,
        EventBusName=bus_name,
        Targets=[{"Id": "sqs-target", "Arn": queue["arn"]}],
    )
    ctx.on_cleanup(
        lambda: events.remove_targets(
            Rule=rule_name, Ids=["sqs-target"], EventBusName=bus_name
        )
    )

    events.put_events(
        Entries=[
            {
                "Source": "app.orders",
                "DetailType": "OrderPlaced",  # does NOT match pattern
                "Detail": json.dumps({"order_id": "no-match"}),
                "EventBusName": bus_name,
            },
            {
                "Source": "app.orders",
                "DetailType": "OrderShipped",  # matches pattern
                "Detail": json.dumps({"order_id": "match-1"}),
                "EventBusName": bus_name,
            },
        ]
    )

    # Drain to quiet rather than stopping at the first message received: a fixed-count wait
    # returns as soon as ANY one message shows up, so a target that (incorrectly) forwarded
    # BOTH entries could still pass whenever the matching one happened to be received first --
    # the non-matching entry would sit unread in the queue and never be checked for absence.
    messages = _drain_to_quiet(ctx, queue["url"], quiet_s=15.0, max_total_s=90.0)
    assert len(messages) == 1, (
        f"expected exactly 1 filtered message, got {len(messages)}: "
        f"{[m['body'] for m in messages]}"
    )
    detail = messages[0]["body"]
    assert detail["detail"]["order_id"] == "match-1", (
        f"expected order_id 'match-1', got {detail['detail'].get('order_id')!r}"
    )
    assert detail["detail-type"] == "OrderShipped", (
        f"expected detail-type 'OrderShipped', got {detail['detail-type']!r}"
    )

    depth = _wait_counters_zero(
        ctx, ctx.client("sqs"), queue["url"],
        ["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )
    assert depth == {
        "ApproximateNumberOfMessages": "0",
        "ApproximateNumberOfMessagesNotVisible": "0",
    }, f"queue still reports {depth!r} after drain -- the non-matching entry may still be in flight"


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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _wait_counters_zero(ctx, sqs, queue_url, names, *, cap_s=90.0, interval_s=3.0):
    """Read the queue's *names* counters until each is "0" or cap_s ends; return the last read.

    SQS documents these counters as eventually consistent: they "may not achieve consistency until
    at least 1 minute after the producers stop sending messages" (GetQueueAttributes).
    """
    start = time.monotonic()
    budget_s = _budget_s(ctx, cap_s)
    stop = start + min(cap_s, budget_s)
    while True:
        attrs = sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=list(names))["Attributes"]
        if all(attrs.get(n) == "0" for n in names):
            return attrs
        if time.monotonic() >= stop:
            if budget_s < cap_s:
                raise TimeoutError(
                    f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before "
                    f"the {cap_s}s counter wait ended (last={attrs!r}); not graded"
                )
            return attrs
        time.sleep(interval_s)


def _drain_to_quiet(ctx, queue_url, quiet_s=15.0, max_total_s=90.0, delete=True):
    """Poll SQS until `quiet_s` elapses with no new message, or `max_total_s` is exhausted.

    Unlike a fixed-count wait, this never stops the instant a message shows up -- it keeps
    draining so a second, wrongly-delivered message is caught rather than left unread.
    """
    sqs = ctx.client("sqs")
    messages: list[dict[str, Any]] = []
    deadline = time.monotonic() + max_total_s
    last_seen = time.monotonic()
    while time.monotonic() < deadline and time.monotonic() - last_seen < quiet_s:
        remaining = max(1, int(deadline - time.monotonic()))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=min(5, remaining),
            MessageAttributeNames=["All"],
        )
        batch = resp.get("Messages", [])
        if batch:
            last_seen = time.monotonic()
        for msg in batch:
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
