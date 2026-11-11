"""eventbridge-fifo-queue-target-arn."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-fifo-queue-target-arn"

GROUP = "arn-resolution"

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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A FIFO queue target delivers with SqsParameters.MessageGroupId, and the same target
    without it is refused with ValidationException and its exact message, leaving no target
    registered."""
    sqs = ctx.client("sqs")
    events = ctx.client("events")

    fifo_name = ctx.unique_name("fifo-q-") + ".fifo"
    fifo = sqs.create_queue(
        QueueName=fifo_name,
        Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true"},
        tags={"sim2real-check": CHECK},
    )
    fifo_url = fifo["QueueUrl"]
    ctx.on_cleanup(lambda: ctx.client("sqs").delete_queue(QueueUrl=fifo_url))
    fifo_arn = sqs.get_queue_attributes(QueueUrl=fifo_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    bus_name = ctx.unique_name("bus-")
    events.create_event_bus(Name=bus_name, Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda: ctx.client("events").delete_event_bus(Name=bus_name))

    rule_name = ctx.unique_name("rule-fifo-")
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

    _set_queue_policy(ctx, fifo_url, _sqs_policy_for_events(fifo_arn, rule_arn))

    # Positive control: with MessageGroupId present, the target Arn resolves and the event is
    # actually delivered -- proof the wiring (policy, rule, bus) works before anything is broken.
    events.put_targets(
        Rule=rule_name,
        EventBusName=bus_name,
        Targets=[
            {
                "Id": "fifo-target",
                "Arn": fifo_arn,
                "SqsParameters": {"MessageGroupId": "orders-group"},
            }
        ],
    )
    ctx.on_cleanup(
        lambda: events.remove_targets(
            Rule=rule_name, Ids=["fifo-target"], EventBusName=bus_name
        )
    )
    # Re-emit until delivered: a fresh rule can drop the first PutEvents; _reemit raises if the
    # event never lands on the FIFO target.
    _reemit_until_delivered(
        ctx,
        fifo_url,
        {
            "Source": "app.orders",
            "DetailType": "OrderPlaced",
            "Detail": json.dumps({"order_id": "fifo-1"}),
            "EventBusName": bus_name,
        },
    )

    # Break exactly one thing: remove the working target, then re-add the identical Arn without
    # SqsParameters.MessageGroupId.
    events.remove_targets(Rule=rule_name, Ids=["fifo-target"], EventBusName=bus_name)
    err, message = _error(
        lambda: events.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[{"Id": "fifo-target", "Arn": fifo_arn}],
        )
    )
    assert err == "ValidationException", (
        f"put_targets against a FIFO queue without SqsParameters.MessageGroupId should fail "
        f"with ValidationException, got {err!r}"
    )
    assert message == "Parameter(s) SqsParameters must be specified for target: fifo-target.", (
        f"unexpected ValidationException message: {message!r}"
    )

    # Effect absent, via an independent read: the rejected call registered nothing.
    remaining = events.list_targets_by_rule(Rule=rule_name, EventBusName=bus_name)["Targets"]
    assert remaining == [], (
        f"put_targets was rejected but a target is still registered: {remaining!r}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(); return the AWS error (Code, Message) if it raised a ClientError. An unexpected
    SUCCESS raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal
    available."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(
        f"expected put_targets to be refused but it SUCCEEDED and returned {result!r}"
    )


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
