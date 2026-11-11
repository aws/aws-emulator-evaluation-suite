"""sqs-target-message-group-id-json-path-resolves-per-event."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "sqs-target-message-group-id-json-path-resolves-per-event"
GROUP = "sqs-target"
SERVICES = ["events"]

_DELIVERY_TIMEOUT_S = 120.0
_RESEND_S = 15.0


def _sqs_policy_for_events(queue_arn: str, rule_arn: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventsSendMessage",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }


def _receive_one(ctx, queue_url: str, event_ids: set[str], timeout_s: float) -> str | None:
    """Poll the FIFO queue for a message carrying one of ``event_ids``; return its MessageGroupId,
    or None once ``timeout_s`` passes."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=5,
            AttributeNames=["MessageGroupId"],
        )
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if body.get("id") in event_ids:
                return msg["Attributes"]["MessageGroupId"]
    return None


def _put_until_delivered(ctx, bus_name: str, queue_url: str, source: str, group_value: str) -> str:
    """Emit an event carrying ``group_value`` until one is delivered; return its MessageGroupId.

    A freshly-created rule or target can drop the first PutEvents silently, so a new event is sent
    every _RESEND_S until the overall timeout, capped by the runner's remaining time.
    """
    events = ctx.client("events")
    timeout_s = _budget_s(ctx, _DELIVERY_TIMEOUT_S)
    deadline = time.monotonic() + timeout_s
    event_ids: set[str] = set()
    while time.monotonic() < deadline:
        resp = events.put_events(
            Entries=[
                {
                    "EventBusName": bus_name,
                    "Source": source,
                    "DetailType": "sim2real.grouped",
                    "Detail": json.dumps({"group": group_value}),
                }
            ]
        )
        assert resp["FailedEntryCount"] == 0, f"PutEvents rejected the entry: {resp['Entries']!r}"
        event_ids.add(resp["Entries"][0]["EventId"])
        wait_s = min(_RESEND_S, max(1.0, deadline - time.monotonic()))
        received = _receive_one(ctx, queue_url, event_ids, wait_s)
        if received is not None:
            return received
    raise TimeoutError(
        f"no event carrying group {group_value!r} reached the FIFO queue within {timeout_s:.0f}s"
    )


def _budget_s(ctx, cap_s):
    """A wait's timeout, bounded by the runner's remaining time so the wait fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """SqsParameters.MessageGroupId holding a JSON path ('$.detail.group') is evaluated per
    event: the received message's MessageGroupId equals that event's own detail.group value,
    not a fixed string.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_SqsParameters.html
    """
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    fifo_name = ctx.unique_name("sim2real-behav-q-") + ".fifo"
    fifo_url = sqs.create_queue(
        QueueName=fifo_name,
        Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true"},
        tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=fifo_url))
    fifo_arn = sqs.get_queue_attributes(QueueUrl=fifo_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    bus_name = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus_name))

    source = ctx.unique_name("sim2real.grouppath.")
    rule_name = ctx.unique_name("sim2real-behav-rule-")
    events.put_rule(
        Name=rule_name, EventBusName=bus_name, EventPattern=json.dumps({"source": [source]}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    def _cleanup_rule() -> None:
        ids = [t["Id"] for t in events.list_targets_by_rule(Rule=rule_name, EventBusName=bus_name)["Targets"]]
        if ids:
            events.remove_targets(Rule=rule_name, EventBusName=bus_name, Ids=ids)
        events.delete_rule(Name=rule_name, EventBusName=bus_name)

    ctx.on_cleanup(_cleanup_rule)
    rule_arn = events.describe_rule(Name=rule_name, EventBusName=bus_name)["Arn"]

    sqs.set_queue_attributes(
        QueueUrl=fifo_url,
        Attributes={"Policy": json.dumps(_sqs_policy_for_events(fifo_arn, rule_arn))},
    )

    put = events.put_targets(
        Rule=rule_name,
        EventBusName=bus_name,
        Targets=[
            {
                "Id": "grouped-target",
                "Arn": fifo_arn,
                "SqsParameters": {"MessageGroupId": "$.detail.group"},
            }
        ],
    )
    assert put["FailedEntryCount"] == 0, f"PutTargets failed: {put['FailedEntries']!r}"

    # Two DIFFERENT group values prove the path is resolved per event, not pinned to one constant.
    first = _put_until_delivered(ctx, bus_name, fifo_url, source, "sim2real-group-alpha")
    assert first == "sim2real-group-alpha", (
        f"first message's MessageGroupId was {first!r}, expected the event's own "
        f"detail.group value 'sim2real-group-alpha'"
    )

    second = _put_until_delivered(ctx, bus_name, fifo_url, source, "sim2real-group-beta")
    assert second == "sim2real-group-beta", (
        f"second message's MessageGroupId was {second!r}, expected the event's own "
        f"detail.group value 'sim2real-group-beta'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
