"""eventbridge-full-envelope-fields-sqs."""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-full-envelope-fields-sqs"

GROUP = "data-format"

SERVICES = ["events", "s3", "sqs"]

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


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


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """EventBridge envelope (source, detail-type, id, time, resources) survives delivery to SQS."""
    events = ctx.client("events")
    queue = _create_queue(ctx)

    bus_name = ctx.unique_name("bus-")
    events.create_event_bus(Name=bus_name)
    ctx.on_cleanup(lambda: ctx.client("events").delete_event_bus(Name=bus_name))

    rule_name = ctx.unique_name("rule-envelope-")
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

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    before = time.time()
    messages = _reemit_until_delivered(
        ctx,
        queue["url"],
        {
            "Source": "app.orders",
            "DetailType": "OrderPlaced",
            "Detail": json.dumps({"order_id": "envelope-1"}),
            "Resources": ["arn:aws:s3:::some-fake-bucket"],
            "EventBusName": bus_name,
        },
    )
    after = time.time()
    envelope = messages[0]["body"]
    for field in (
        "version",
        "id",
        "source",
        "account",
        "time",
        "region",
        "detail-type",
        "detail",
        "resources",
    ):
        assert field in envelope, f"missing envelope field {field!r}: {envelope}"
    assert envelope["source"] == "app.orders"
    assert envelope["detail-type"] == "OrderPlaced"
    assert envelope["resources"] == ["arn:aws:s3:::some-fake-bucket"]
    # These fields are the ones a stub echoing the PutEvents input verbatim cannot fabricate:
    # they are assigned by EventBridge itself, so only a real delivery can produce correct values.
    assert envelope["version"] == "0", f"expected envelope version '0', got {envelope['version']!r}"
    assert _UUID_RE.match(envelope["id"] or ""), f"envelope id is not a UUID: {envelope['id']!r}"
    assert envelope["account"] == account_id, (
        f"expected envelope account {account_id!r}, got {envelope['account']!r}"
    )
    assert envelope["region"] == ctx.region, (
        f"expected envelope region {ctx.region!r}, got {envelope['region']!r}"
    )
    event_dt = datetime.strptime(envelope["time"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    event_epoch = event_dt.timestamp()
    assert before - 5 <= event_epoch <= after + 5, (
        f"envelope time {envelope['time']!r} ({event_epoch}) outside the call window "
        f"[{before}, {after}]"
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
