"""nested-or-inside-detail-agrees-between-test-event-pattern-and-real-delivery."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nested-or-inside-detail-agrees-between-test-event-pattern-and-real-delivery"
GROUP = "test-event-pattern"
SERVICES = ["events"]


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """`$or` nested inside `detail` is accepted, and TestEventPattern's verdict for each branch and
    a miss agrees with what a live rule actually delivers to an SQS target.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-pattern-operators.html
    """
    events = ctx.client("events")
    bus = _create_bus(ctx, events)
    source = ctx.unique_name("sim2real.nestedor.")
    pattern = {
        "source": [source],
        "detail": {"$or": [{"tier": ["gold"]}, {"amount": [{"numeric": [">", 1000]}]}]},
    }

    def entry(marker: str, tier: str, amount: int) -> dict:
        return {
            "EventBusName": bus, "Source": source, "DetailType": "sim2real-order",
            "Detail": json.dumps({"marker": marker, "tier": tier, "amount": amount}),
        }

    def envelope(tier: str, amount: int) -> dict:
        return {
            "id": "11111111-2222-3333-4444-555555555555", "version": "0",
            "detail-type": "sim2real-order", "source": source, "account": ctx.account,
            "time": "2024-01-01T00:00:00Z", "region": ctx.region, "resources": [],
            "detail": {"marker": "x", "tier": tier, "amount": amount},
        }

    # --- establish the synchronous verdict for all three cases before touching a live rule --
    cases = {
        "first-branch": (envelope("gold", 1), True),
        "second-branch": (envelope("silver", 5000), True),
        "neither-branch": (envelope("silver", 1), False),
    }
    for label, (env, want) in cases.items():
        resp = events.test_event_pattern(EventPattern=json.dumps(pattern), Event=json.dumps(env))
        assert resp["Result"] is want, (
            f"TestEventPattern disagreed with the expected verdict for {label!r}: "
            f"expected Result={want}, got {resp['Result']}\n  event = {json.dumps(env)}"
        )

    # --- a live rule with the same nested $or pattern, aimed at an SQS target ---------------
    rule_name, rule_arn = _put_rule(ctx, events, bus, pattern)
    queue_url, queue_arn = _create_queue_with_eventbridge_policy(ctx, rule_arn)
    _put_target(ctx, events, bus, rule_name, queue_arn)
    # A source-only twin rule on its own queue proves the bus dispatched every entry, so an
    # absence at the primary queue is the pattern's verdict and not a delivery that never ran.
    control_name, control_arn = _put_rule(ctx, events, bus, {"source": [source]})
    control_url, control_queue_arn = _create_queue_with_eventbridge_policy(ctx, control_arn)
    _put_target(ctx, events, bus, control_name, control_queue_arn)

    first_marker = ctx.unique_name("first-branch-")
    second_marker = ctx.unique_name("second-branch-")
    near_miss_marker = ctx.unique_name("neither-branch-")
    resp = events.put_events(Entries=[
        entry(first_marker, "gold", 1),
        entry(second_marker, "silver", 5000),
        entry(near_miss_marker, "silver", 1),
    ])
    assert resp["FailedEntryCount"] == 0, f"PutEvents rejected an entry: {resp['Entries']!r}"

    _collect_markers(ctx, control_url, {first_marker, second_marker, near_miss_marker}, timeout_s=90.0)
    delivered = set(_drain(ctx, queue_url))
    assert delivered == {first_marker, second_marker}, (
        f"the live rule's deliveries must match TestEventPattern's verdict: expected "
        f"{{{first_marker!r}, {second_marker!r}}} (both $or branches), got {delivered!r}"
    )
    assert near_miss_marker not in delivered, (
        f"an event matching neither $or branch was delivered: {near_miss_marker!r}"
    )


def _create_bus(ctx, events) -> str:
    bus = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))
    return bus


def _put_rule(ctx, events, bus: str, pattern: dict) -> tuple[str, str]:
    name = ctx.unique_name("sim2real-behav-rule-")
    arn = events.put_rule(
        Name=name, EventBusName=bus, EventPattern=json.dumps(pattern), State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda n=name: _ignore_not_found(
        lambda: events.delete_rule(Name=n, EventBusName=bus)))
    return name, arn


def _put_target(ctx, events, bus: str, rule_name: str, target_arn: str) -> None:
    resp = events.put_targets(
        Rule=rule_name, EventBusName=bus,
        Targets=[{"Id": "sim2real-target", "Arn": target_arn}],
    )
    assert resp["FailedEntryCount"] == 0, f"put_targets failed: {resp}"
    ctx.on_cleanup(lambda n=rule_name: _ignore_not_found(
        lambda: events.remove_targets(Rule=n, EventBusName=bus, Ids=["sim2real-target"])))


def _create_queue_with_eventbridge_policy(ctx, rule_arn: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    queue_name = ctx.unique_name("sim2real-evb-queue-")
    queue_url = sqs.create_queue(QueueName=queue_name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowEventBridgeDelivery", "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"}, "Action": "sqs:SendMessage",
            "Resource": queue_arn, "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    return queue_url, queue_arn


def _marker_of(body: dict):
    return body["detail"].get("marker") if isinstance(body.get("detail"), dict) else None


def _collect_markers(ctx, queue_url: str, wanted: set, timeout_s: float) -> None:
    """Drain until every marker in `wanted` has arrived on the queue."""
    sqs = ctx.client("sqs")
    seen: set = set()
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and not wanted <= seen:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            seen.add(_marker_of(json.loads(msg["Body"])))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    assert wanted <= seen, (
        f"control queue received {sorted(m for m in seen if m)} within {timeout_s}s, "
        f"expected {sorted(wanted)}"
    )


def _drain(ctx, queue_url: str) -> list:
    """Receive until one empty long poll; return the markers of every message drained."""
    sqs = ctx.client("sqs")
    markers = []
    while True:
        msgs = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        ).get("Messages", [])
        if not msgs:
            return markers
        for msg in msgs:
            markers.append(_marker_of(json.loads(msg["Body"])))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
