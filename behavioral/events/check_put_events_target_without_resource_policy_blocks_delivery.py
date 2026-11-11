"""put-events-target-without-resource-policy-blocks-delivery."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "put-events-target-without-resource-policy-blocks-delivery"
GROUP = "telemetry"
SERVICES = ["events"]


@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """On one rule, an SQS target without a queue policy granting events.amazonaws.com never receives the
    matching event while a sibling queue with that policy does: PutTargets alone grants no delivery."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    rule_name = ctx.unique_name("sim2real-evb-rule-")
    source = ctx.unique_name("sim2real.policytest.")
    detail_type = "sim2real-policy-type"

    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps({"source": [source], "detail-type": [detail_type]}),
        State="ENABLED",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    # Negative subject: queue with NO resource policy granting EventBridge send permission.
    no_policy_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-nopolicy-"),
        tags={"sim2real-check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=no_policy_url))
    no_policy_arn = sqs.get_queue_attributes(
        QueueUrl=no_policy_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    # Positive control: an otherwise-identical queue WITH the policy.
    policy_url, policy_arn = _create_queue_with_eventbridge_policy(ctx, rule_arn)

    put_targets_resp = events.put_targets(
        Rule=rule_name,
        Targets=[
            {"Id": "no-policy-target", "Arn": no_policy_arn},
            {"Id": "with-policy-target", "Arn": policy_arn},
        ],
    )
    ctx.on_cleanup(
        lambda: events.remove_targets(Rule=rule_name, Ids=["no-policy-target", "with-policy-target"])
    )
    # EventBridge does not validate SQS resource-policy permissions synchronously at
    # PutTargets time -- both targets are accepted.
    assert put_targets_resp["FailedEntryCount"] == 0, (
        f"expected PutTargets to accept both targets synchronously (FailedEntryCount=0), "
        f"got FailedEntryCount={put_targets_resp['FailedEntryCount']} entries={put_targets_resp.get('FailedEntries')}"
    )

    marker = ctx.unique_name("marker-")
    events.put_events(
        Entries=[{"Source": source, "DetailType": detail_type, "Detail": json.dumps({"marker": marker})}]
    )

    # Positive control must actually receive the event.
    delivered = _poll_for_marker(ctx, policy_url, marker, timeout_s=60.0)
    assert delivered["detail"]["marker"] == marker, (
        f"positive control queue {policy_url} received an event but its marker did not "
        f"match: expected {marker!r}, got {delivered['detail'].get('marker')!r}"
    )

    # Negative subject must never receive it, even after the control has already arrived.
    resp = sqs.receive_message(QueueUrl=no_policy_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
    assert not resp.get("Messages"), (
        "event was delivered to an SQS target lacking a resource policy granting EventBridge access"
    )


def _create_queue_with_eventbridge_policy(ctx, rule_arn: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    queue_name = ctx.unique_name("sim2real-evb-queue-")
    queue_url = sqs.create_queue(
        QueueName=queue_name, tags={"sim2real-check": CHECK}
    )["QueueUrl"]
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


def _poll_for_marker(ctx, queue_url: str, marker: str, timeout_s: float = 60.0) -> dict:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if isinstance(body.get("detail"), dict) and body["detail"].get("marker") == marker:
                return body
    raise AssertionError(f"event with marker {marker} was never delivered to {queue_url} within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
