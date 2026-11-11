"""cmk-encrypted-bus-delivers-put-events-to-sqs-target."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "cmk-encrypted-bus-delivers-put-events-to-sqs-target"
GROUP = "event-bus"
SERVICES = ["events"]

_DELIVERY_TIMEOUT_S = 90.0


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:eventing",
      "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A bus encrypted with a customer-managed KMS key reports that key and still delivers a
    matching event to the rule's SQS target with its id, source and detail intact."""
    events = ctx.client("events")
    kms = ctx.client("kms")

    bus = ctx.unique_name("sim2real-behav-bus-")
    bus_arn = f"arn:aws:events:{ctx.region}:{ctx.account}:event-bus/{bus}"
    key_arn = _create_bus_key(ctx, kms, bus_arn)

    created = events.create_event_bus(
        Name=bus, KmsKeyIdentifier=key_arn, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))
    assert created["EventBusArn"] == bus_arn, (
        f"CreateEventBus returned ARN {created['EventBusArn']!r}, expected {bus_arn!r}"
    )
    described = events.describe_event_bus(Name=bus)
    assert described.get("KmsKeyIdentifier") == key_arn, (
        f"DescribeEventBus must report the customer key the bus was created with: expected "
        f"{key_arn!r}, got {described.get('KmsKeyIdentifier')!r}"
    )

    source = ctx.unique_name("sim2real.cmk.")
    rule = ctx.unique_name("sim2real-behav-rule-")
    rule_arn = events.put_rule(
        Name=rule, EventBusName=bus, State="ENABLED",
        EventPattern=json.dumps({"source": [source]}),
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule, EventBusName=bus))

    queue_url, queue_arn = _create_queue_for_rule(ctx, rule_arn)
    put_targets = events.put_targets(
        Rule=rule, EventBusName=bus, Targets=[{"Id": "sim2real-q", "Arn": queue_arn}]
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule, EventBusName=bus, Ids=["sim2real-q"]))
    assert put_targets["FailedEntryCount"] == 0, f"PutTargets failed: {put_targets['FailedEntries']!r}"

    marker = ctx.unique_name("marker-")
    detail = {"marker": marker, "nested": {"amount": 42, "tags": ["a", "b"]}}
    put = events.put_events(Entries=[{
        "EventBusName": bus, "Source": source, "DetailType": "sim2real-cmk",
        "Detail": json.dumps(detail),
    }])
    assert put["FailedEntryCount"] == 0, (
        f"PutEvents to the CMK-encrypted bus must accept the entry, got {put['Entries']!r}"
    )
    event_id = put["Entries"][0]["EventId"]

    envelope = _poll_for_marker(ctx, queue_url, marker)
    assert envelope["id"] == event_id, (
        f"delivered envelope id {envelope['id']!r} does not match the PutEvents EventId {event_id!r}"
    )
    assert envelope["source"] == source, f"delivered source {envelope['source']!r}, expected {source!r}"
    assert envelope["detail"] == detail, (
        f"the detail must survive encryption under the customer key unchanged: sent {detail!r}, "
        f"received {envelope['detail']!r}"
    )
    assert envelope["resources"] == [], f"expected an empty resources list, got {envelope['resources']!r}"


def _create_bus_key(ctx, kms, bus_arn: str) -> str:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AccountAdmin",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "AllowEventBridgeForTheBus",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"],
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:SourceAccount": ctx.account}},
            },
        ],
    }
    meta = kms.create_key(
        Description=f"sim2real {CHECK}",
        Policy=json.dumps(policy),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=meta["KeyId"], PendingWindowInDays=7))
    return meta["Arn"]


def _create_queue_for_rule(ctx, rule_arn: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-q-")
    url = sqs.create_queue(QueueName=name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return url, arn


def _poll_for_marker(ctx, queue_url: str, marker: str) -> dict:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + _DELIVERY_TIMEOUT_S
    seen = 0
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            seen += 1
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if isinstance(body.get("detail"), dict) and body["detail"].get("marker") == marker:
                return body
    raise AssertionError(
        f"the event put to the CMK-encrypted bus never reached the SQS target within "
        f"{_DELIVERY_TIMEOUT_S}s ({seen} unrelated messages seen)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
