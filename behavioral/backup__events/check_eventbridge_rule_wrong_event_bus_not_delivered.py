"""eventbridge-rule-wrong-event-bus-not-delivered."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-rule-wrong-event-bus-not-delivered"
GROUP = "overly-permissive"
SERVICES = ["backup", "events"]


@tags(
    "axis:negative-delivery",
    "cap:c1",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A rule on a custom event bus does not receive a Backup-shaped event published to the default
    bus, while a rule with the same pattern on the default bus does; the event uses a custom
    source because 'aws.*' is reserved."""
    events = ctx.client("events")

    custom_bus_name = ctx.unique_name("sim2real-bus-")
    events.create_event_bus(Name=custom_bus_name)
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=custom_bus_name))

    source = ctx.unique_name("sim2real.backup.busisolation.")
    pattern = {"source": [source], "detail-type": ["Backup Job State Change"]}

    custom_rule_name = ctx.unique_name("sim2real-rule-custom-")
    custom_rule_arn = events.put_rule(
        Name=custom_rule_name,
        EventPattern=json.dumps(pattern),
        EventBusName=custom_bus_name,
    )["RuleArn"]
    ctx.on_cleanup(
        lambda: events.delete_rule(Name=custom_rule_name, EventBusName=custom_bus_name)
    )
    custom_queue = _create_events_queue(ctx, custom_rule_arn)
    events.put_targets(
        Rule=custom_rule_name,
        EventBusName=custom_bus_name,
        Targets=[{"Id": "t1", "Arn": custom_queue["arn"]}],
    )
    ctx.on_cleanup(
        lambda: events.remove_targets(
            Rule=custom_rule_name, EventBusName=custom_bus_name, Ids=["t1"]
        )
    )

    default_rule_name = ctx.unique_name("sim2real-rule-default-")
    default_rule_arn = events.put_rule(
        Name=default_rule_name, EventPattern=json.dumps(pattern)
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=default_rule_name))
    default_queue = _create_events_queue(ctx, default_rule_arn)
    events.put_targets(
        Rule=default_rule_name, Targets=[{"Id": "t1", "Arn": default_queue["arn"]}]
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=default_rule_name, Ids=["t1"]))

    marker = str(uuid.uuid4())
    # Published to the DEFAULT bus (no EventBusName), exactly as AWS Backup's own integration does.
    put_resp = events.put_events(
        Entries=[
            {
                "Source": source,
                "DetailType": "Backup Job State Change",
                "Detail": json.dumps({"backupJobId": marker, "state": "COMPLETED"}),
            }
        ]
    )
    assert put_resp["FailedEntryCount"] == 0, (
        f"put_events failed entries: {put_resp['Entries']}"
    )

    event = _wait_for_event_matching(
        ctx,
        default_queue["url"],
        lambda evt: _job_id_in(evt, marker),
        timeout_s=60.0,
        interval_s=5.0,
    )
    assert event["detail"]["backupJobId"] == marker, (
        f"expected backupJobId {marker!r} on default-bus rule's queue, got {event['detail'].get('backupJobId')!r}"
    )

    _assert_no_message_matching(
        ctx, custom_queue["url"], lambda evt: _job_id_in(evt, marker), duration_s=20.0
    )


def _job_id_in(evt: dict[str, Any], marker: str) -> bool:
    return evt.get("detail", {}).get("backupJobId") == marker


def _create_events_queue(ctx, rule_arn: str) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-evtq-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return {"url": url, "arn": arn}


def _wait_for_event_matching(
    ctx, queue_url: str, match_fn, timeout_s: float = 90.0, interval_s: float = 3.0
) -> dict[str, Any]:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10
        )
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if match_fn(body):
                return body
        time.sleep(max(0.0, interval_s - 10.0))
    raise AssertionError(
        f"no matching event arrived on {queue_url} within {timeout_s}s"
    )


def _assert_no_message_matching(
    ctx, queue_url: str, match_fn, duration_s: float = 20.0
) -> None:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + duration_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10
        )
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if match_fn(body):
                raise AssertionError(
                    f"custom-bus rule unexpectedly received a default-bus event: {body}"
                )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
