"""put-events-missing-source-entry-fails."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags


CHECK = "put-events-missing-source-entry-fails"
GROUP = 'put-events'
SERVICES = ['events']

@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PutEvents entry without Source fails at the entry level with InvalidArgument, no EventId
    and no delivery, while a well-formed entry in the same batch gets an EventId and is delivered
    to the rule's SQS target."""
    events = ctx.client("events")

    rule_name = ctx.unique_name("sim2real-evb-rule-")
    source = ctx.unique_name("sim2real.source.")
    detail_type = "sim2real-missing-source-type"

    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps({"source": [source], "detail-type": [detail_type]}),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    queue_url, queue_arn = _create_queue_with_eventbridge_policy(ctx, rule_arn)

    events.put_targets(Rule=rule_name, Targets=[{"Id": "sim2real-target", "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["sim2real-target"]))

    targets = events.list_targets_by_rule(Rule=rule_name)["Targets"]
    assert any(t["Arn"] == queue_arn for t in targets), "target was not registered on the rule"

    good_marker = ctx.unique_name("good-marker-")
    bad_marker = ctx.unique_name("bad-marker-")
    resp = events.put_events(
        Entries=[
            {
                "Source": source,
                "DetailType": detail_type,
                "Detail": json.dumps({"marker": good_marker}),
            },
            {
                # No Source at all -- entry-level validation, not a bad but present value.
                "DetailType": detail_type,
                "Detail": json.dumps({"marker": bad_marker}),
            },
        ]
    )
    assert resp["FailedEntryCount"] == 1, f"expected exactly 1 failed entry, got {resp}"
    entries = resp["Entries"]
    assert len(entries) == 2, f"PutEvents must return one result per request entry, got {entries}"

    good_entry, bad_entry = entries
    assert good_entry.get("EventId"), (
        f"the well-formed entry (positive control) must carry an EventId, got {good_entry}"
    )
    assert "ErrorCode" not in good_entry, (
        f"the well-formed entry must not carry an ErrorCode, got {good_entry}"
    )

    assert bad_entry.get("ErrorCode") == "InvalidArgument", (
        f"an entry missing Source must fail with ErrorCode=InvalidArgument, got "
        f"{bad_entry.get('ErrorCode')!r}: {bad_entry}"
    )
    expected_message = "Parameter Source is not valid. Reason: Source is a required argument."
    assert bad_entry.get("ErrorMessage") == expected_message, (
        f"the per-entry ErrorMessage must be {expected_message!r}, got "
        f"{bad_entry.get('ErrorMessage')!r}"
    )
    assert not bad_entry.get("EventId"), (
        f"a failed entry must not carry an EventId, got {bad_entry.get('EventId')!r}"
    )

    seen_markers = _drain_until_marker_seen(ctx, queue_url, good_marker, timeout_s=60.0)
    assert good_marker in seen_markers, "the well-formed entry (positive control) was never delivered"
    assert bad_marker not in seen_markers, (
        "the entry missing Source was delivered to the rule's target even though it was rejected "
        "at PutEvents and never assigned an EventId"
    )




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
        "Statement": [
            {
                "Sid": "AllowEventBridgeDelivery",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    return queue_url, queue_arn


def _drain_until_marker_seen(ctx, queue_url: str, target_marker: str, timeout_s: float) -> set[str]:
    sqs = ctx.client("sqs")
    seen: set[str] = set()
    deadline = time.monotonic() + timeout_s
    found_target = False
    while time.monotonic() < deadline and not found_target:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            marker = body.get("detail", {}).get("marker") if isinstance(body.get("detail"), dict) else None
            if marker:
                seen.add(marker)
                if marker == target_marker:
                    found_target = True
    if not found_target:
        raise AssertionError(f"target marker {target_marker} never arrived within {timeout_s}s")
    return seen


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
