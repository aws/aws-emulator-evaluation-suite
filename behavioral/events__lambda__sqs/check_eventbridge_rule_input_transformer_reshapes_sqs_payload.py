"""eventbridge-rule-input-transformer-reshapes-sqs-payload."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-rule-input-transformer-reshapes-sqs-payload"
GROUP = "data-format"
SERVICES = ["events", "lambda", "sqs"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """EventBridge InputTransformer reshapes the matched event before it lands in the SQS
    target message body — the queue receives the transformed template, not the raw event
    envelope."""
    queue = _create_queue_with_events_policy(ctx)

    rule = _put_rule(
        ctx,
        pattern={"source": ["sim2real.shipping"], "detail-type": ["PackageShipped"]},
    )
    _put_targets(
        ctx,
        rule["name"],
        [
            {
                "Id": "sqs-target",
                "Arn": queue["arn"],
                "InputTransformer": {
                    "InputPathsMap": {
                        "tracking": "$.detail.trackingId",
                        "carrier": "$.detail.carrier",
                    },
                    "InputTemplate": (
                        '{"trackingId": <tracking>, "carrier": <carrier>, '
                        '"status": "reshaped"}'
                    ),
                },
            }
        ],
    )

    events = ctx.client("events")
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.shipping",
                "DetailType": "PackageShipped",
                "Detail": json.dumps({"trackingId": "TRK-999", "carrier": "ups"}),
            }
        ]
    )

    messages = _wait_for_messages(ctx, queue["url"], expected_count=1, timeout_s=60.0)
    assert len(messages) >= 1, f"expected at least 1 message, got {len(messages)}"
    body = json.loads(messages[0]["Body"])
    assert body == {
        "trackingId": "TRK-999",
        "carrier": "ups",
        "status": "reshaped",
    }, body


def _create_queue_with_events_policy(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-ebl-q-")
    url = sqs.create_queue(QueueName=name, tags={"sim2real:managed": "true"})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    account_id = arn.split(":")[4]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridge",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": arn,
                "Condition": {
                    "ArnEquals": {
                        "aws:SourceArn": f"arn:aws:events:{ctx.region}:{account_id}:rule/*"
                    }
                },
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return {"url": url, "arn": arn}


def _drain_queue(ctx, queue_url, max_messages=10, wait_s=2):
    sqs = ctx.client("sqs")
    out = []
    resp = sqs.receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=max_messages, WaitTimeSeconds=wait_s
    )
    for msg in resp.get("Messages", []):
        out.append(msg)
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _wait_for_messages(ctx, queue_url, expected_count=1, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    out = []
    while time.monotonic() < deadline and len(out) < expected_count:
        out.extend(_drain_queue(ctx, queue_url, wait_s=5))
    if len(out) < expected_count:
        raise AssertionError(f"expected {expected_count} messages, got {len(out)}")
    return out


def _put_rule(ctx, pattern=None, schedule=None, state="ENABLED", event_bus_name=None):
    events = ctx.client("events")
    name = ctx.unique_name("sim2real-ebl-rule-")
    kwargs: dict[str, Any] = {"Name": name, "State": state}
    if pattern is not None:
        kwargs["EventPattern"] = json.dumps(pattern)
    if schedule is not None:
        kwargs["ScheduleExpression"] = schedule
    if event_bus_name:
        kwargs["EventBusName"] = event_bus_name
    kwargs["Tags"] = [{"Key": "sim2real:managed", "Value": "true"}]
    resp = events.put_rule(**kwargs)
    if event_bus_name:
        ctx.on_cleanup(lambda: events.delete_rule(Name=name, EventBusName=event_bus_name))
    else:
        ctx.on_cleanup(lambda: events.delete_rule(Name=name))
    return {"name": name, "arn": resp["RuleArn"]}


def _put_targets(ctx, rule_name, targets, event_bus_name=None):
    events = ctx.client("events")
    kwargs: dict[str, Any] = {"Rule": rule_name, "Targets": targets}
    if event_bus_name:
        kwargs["EventBusName"] = event_bus_name
    resp = events.put_targets(**kwargs)
    if resp.get("FailedEntryCount", 0):
        raise AssertionError(f"put_targets failures: {resp['FailedEntries']}")
    ids = [t["Id"] for t in targets]

    def _cleanup():
        kw: dict[str, Any] = {"Rule": rule_name, "Ids": ids}
        if event_bus_name:
            kw["EventBusName"] = event_bus_name
        events.remove_targets(**kw)

    ctx.on_cleanup(_cleanup)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
