"""eventbridge-rule-to-sqs-target."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-rule-to-sqs-target"

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


def _error(fn) -> tuple[str, str]:
    """Run fn; return the ClientError (Code, Message). Raises if fn unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError("expected a ClientError, call unexpectedly succeeded")


def _unless_gone(fn) -> None:
    """Teardown for a resource the check deletes itself: a ResourceNotFoundException is done."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A custom EventBridge rule delivers matching put_events entries to SQS; the target
    registration is independently visible via list_targets_by_rule before delivery; and once
    the target/rule/bus are deleted, an independent read at each shows it gone."""
    events = ctx.client("events")
    queue = _create_queue(ctx)

    bus_name = ctx.unique_name("bus-")
    events.create_event_bus(Name=bus_name, Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda: ctx.client("events").delete_event_bus(Name=bus_name))

    rule_name = ctx.unique_name("rule-")
    events.put_rule(
        Name=rule_name,
        EventBusName=bus_name,
        EventPattern=json.dumps(
            {"source": ["app.orders"], "detail-type": ["OrderPlaced"]}
        ),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(
        lambda: _unless_gone(
            lambda: ctx.client("events").delete_rule(Name=rule_name, EventBusName=bus_name)
        )
    )
    rule_arn = _rule_arn(ctx, rule_name, bus_name)

    _set_queue_policy(ctx, queue["url"], _sqs_policy_for_events(queue["arn"], rule_arn))
    events.put_targets(
        Rule=rule_name,
        EventBusName=bus_name,
        Targets=[{"Id": "sqs-target", "Arn": queue["arn"]}],
    )
    ctx.on_cleanup(
        lambda: _unless_gone(
            lambda: events.remove_targets(
                Rule=rule_name, Ids=["sqs-target"], EventBusName=bus_name
            )
        )
    )
    registered = events.list_targets_by_rule(Rule=rule_name, EventBusName=bus_name)["Targets"]
    assert [t["Arn"] for t in registered] == [queue["arn"]], (
        f"expected the queue registered as the rule's only target, got {registered!r}"
    )

    messages = _reemit_until_delivered(
        ctx,
        queue["url"],
        {
            "Source": "app.orders",
            "DetailType": "OrderPlaced",
            "Detail": json.dumps({"order_id": "abc123"}),
            "EventBusName": bus_name,
        },
    )
    detail = messages[0]["body"]
    assert detail["detail"]["order_id"] == "abc123", (
        f"expected delivered detail.order_id == 'abc123', got {detail!r}"
    )

    events.remove_targets(Rule=rule_name, Ids=["sqs-target"], EventBusName=bus_name)
    after_remove = events.list_targets_by_rule(Rule=rule_name, EventBusName=bus_name)["Targets"]
    assert after_remove == [], f"expected no targets after remove_targets, got {after_remove!r}"

    events.delete_rule(Name=rule_name, EventBusName=bus_name)
    code, message = _error(lambda: events.describe_rule(Name=rule_name, EventBusName=bus_name))
    assert code == "ResourceNotFoundException", (
        f"expected describe_rule on a deleted rule to fail ResourceNotFoundException, got {code!r}"
    )
    assert message == f"Rule {rule_name} does not exist on EventBus {bus_name}.", (
        f"unexpected describe_rule message: {message!r}"
    )

    events.delete_event_bus(Name=bus_name)
    code, message = _error(lambda: events.describe_event_bus(Name=bus_name))
    assert code == "ResourceNotFoundException", (
        f"expected describe_event_bus on a deleted bus to fail ResourceNotFoundException, got {code!r}"
    )
    assert message == f"Event bus {bus_name} does not exist.", (
        f"unexpected describe_event_bus message: {message!r}"
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


def _reemit_until_delivered(ctx, queue_url, entry, *, attempts=8, poll_s=6.0):
    """Emit an EventBridge event repeatedly until it lands on the SQS queue; return the messages list.
    A freshly-created rule/target can silently drop the first PutEvents before the path is live, and
    EventBridge never retries a dropped event, so re-emitting is more reliable than one longer wait.
    Raises AssertionError if never delivered."""
    events = ctx.client("events")
    for _ in range(attempts):
        events.put_events(Entries=[entry])
        messages = _receive_messages(ctx, queue_url, expected_count=1, timeout_s=poll_s)
        if messages:
            return messages
    raise AssertionError(
        f"event never delivered to {queue_url} after {attempts} attempts of {poll_s}s each"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
