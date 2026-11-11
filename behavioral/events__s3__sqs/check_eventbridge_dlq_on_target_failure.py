"""eventbridge-dlq-on-target-failure."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-dlq-on-target-failure"

GROUP = "error-propagation"

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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An event an unauthorized SQS target cannot receive lands in the target DLQ with
    ERROR_CODE NO_RESOURCE and the target ARN; once the queue policy is granted the same target
    receives the next event directly."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    unauthorized_queue = _create_queue(ctx)  # no policy: delivery will fail
    dlq = _create_queue(ctx)

    bus_name = ctx.unique_name("bus-")
    events.create_event_bus(Name=bus_name)
    ctx.on_cleanup(lambda: ctx.client("events").delete_event_bus(Name=bus_name))

    rule_name = ctx.unique_name("rule-dlq-")
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

    # DLQ needs a policy allowing events.amazonaws.com to send the failed event.
    _set_queue_policy(ctx, dlq["url"], _sqs_policy_for_events(dlq["arn"], rule_arn))

    events.put_targets(
        Rule=rule_name,
        EventBusName=bus_name,
        Targets=[
            {
                "Id": "unauthorized-target",
                "Arn": unauthorized_queue["arn"],
                "RetryPolicy": {
                    "MaximumRetryAttempts": 0,
                    "MaximumEventAgeInSeconds": 60,
                },
                "DeadLetterConfig": {"Arn": dlq["arn"]},
            }
        ],
    )
    ctx.on_cleanup(
        lambda: events.remove_targets(
            Rule=rule_name, Ids=["unauthorized-target"], EventBusName=bus_name
        )
    )

    dlq_messages = _reemit_until_delivered(
        ctx,
        dlq["url"],
        {
            "Source": "app.orders",
            "DetailType": "OrderPlaced",
            "Detail": json.dumps({"order_id": "dlq-1"}),
            "EventBusName": bus_name,
        },
    )
    dlq_body = dlq_messages[0]["body"]
    assert dlq_body.get("detail") == {"order_id": "dlq-1"}, (
        f"DLQ message does not carry the failed event's own detail: {dlq_body!r}"
    )
    dlq_attrs = dlq_messages[0]["attributes"]
    # SQS answers an unauthorized SendMessage as a missing queue, so EventBridge files NO_RESOURCE.
    # message varies: ERROR_MESSAGE embeds SQS's per-request Request ID.
    assert dlq_attrs.get("ERROR_CODE", {}).get("StringValue") == "NO_RESOURCE", (
        f"expected ERROR_CODE=NO_RESOURCE on the DLQ message, got {dlq_attrs!r}"
    )
    assert dlq_attrs.get("TARGET_ARN", {}).get("StringValue") == unauthorized_queue["arn"], (
        f"expected TARGET_ARN={unauthorized_queue['arn']!r} on the DLQ message, got {dlq_attrs!r}"
    )

    # Effect absent: the unauthorized target never received the event directly.
    leaked = sqs.receive_message(
        QueueUrl=unauthorized_queue["url"], MaxNumberOfMessages=10, WaitTimeSeconds=5
    ).get("Messages", [])
    assert not leaked, (
        f"unauthorized target received the event despite missing policy: {leaked!r}"
    )

    # Positive control: grant the missing policy and prove the identical rule/target now
    # delivers directly, so the DLQ capture above was genuinely failure-triggered and not a
    # target that unconditionally routes to its DeadLetterConfig.
    _set_queue_policy(
        ctx,
        unauthorized_queue["url"],
        _sqs_policy_for_events(unauthorized_queue["arn"], rule_arn),
    )
    direct_messages = _reemit_until_delivered(
        ctx,
        unauthorized_queue["url"],
        {
            "Source": "app.orders",
            "DetailType": "OrderPlaced",
            "Detail": json.dumps({"order_id": "dlq-2-authorized"}),
            "EventBusName": bus_name,
        },
    )
    assert direct_messages[0]["body"].get("detail") == {"order_id": "dlq-2-authorized"}, (
        f"authorized target did not receive the expected event directly: "
        f"{direct_messages[0]['body']!r}"
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
