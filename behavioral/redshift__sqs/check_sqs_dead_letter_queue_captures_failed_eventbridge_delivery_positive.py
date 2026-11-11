"""sqs-dead-letter-queue-captures-failed-eventbridge-delivery-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "sqs-dead-letter-queue-captures-failed-eventbridge-delivery-positive"
GROUP = "delivery"
SERVICES = ["redshift", "sqs"]


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """When a rule's target queue lacks a policy for events.amazonaws.com, the target's DLQ captures the
    event with its RULE_ARN and error code NO_PERMISSIONS, and after the policy is granted the
    target receives a new event."""
    dlq = _create_queue(ctx, "dlq-capture-dlq")
    target = _create_queue(ctx, "dlq-capture-target")  # intentionally left policy-less

    rule = _create_rule(
        ctx, "dlq-capture-rule", {"source": ["sim2real.dlqtest"], "detail-type": ["DLQ Capture Test"]}
    )
    # The DLQ itself needs the same grant, scoped to this rule's ARN.
    _set_queue_policy(ctx, dlq, rule["arn"])
    _put_target(
        ctx,
        rule["name"],
        "1",
        target["arn"],
        DeadLetterConfig={"Arn": dlq["arn"]},
        RetryPolicy={"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
    )

    token = ctx.unique_name("sim2real-dlq-token-")
    events = ctx.client("events")
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.dlqtest",
                "DetailType": "DLQ Capture Test",
                "Detail": json.dumps({"token": token}),
            }
        ]
    )

    dlq_messages = _poll_messages(ctx, dlq["url"], min_count=1, timeout_s=150.0)
    assert len(dlq_messages) >= 1, "failed delivery was never captured by the DLQ"
    msg = dlq_messages[0]
    body = json.loads(msg["Body"])
    assert body["detail"]["token"] == token, (
        f"expected captured event to carry token {token!r}, got {body.get('detail')}"
    )
    attrs = msg.get("MessageAttributes", {})
    assert attrs.get("RULE_ARN", {}).get("StringValue") == rule["arn"], (
        f"expected RULE_ARN={rule['arn']!r} on the DLQ message, got {attrs.get('RULE_ARN')}"
    )
    error_code = attrs.get("ERROR_CODE", {}).get("StringValue")
    assert error_code == "NO_PERMISSIONS", (
        f"expected ERROR_CODE=NO_PERMISSIONS (missing SQS resource policy), got {error_code!r}"
    )

    # The failed event must never have reached the (policy-less) primary target.
    _assert_absent(ctx, target["url"], timeout_s=20.0)

    # Restore: the missing queue policy was the only broken thing, so granting it
    # and resending the identical kind of event must now succeed at the target —
    # otherwise "captured by the DLQ" could just mean "never delivered at all".
    _set_queue_policy(ctx, target, rule["arn"])
    restore_token = ctx.unique_name("sim2real-dlq-restore-")
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.dlqtest",
                "DetailType": "DLQ Capture Test",
                "Detail": json.dumps({"token": restore_token}),
            }
        ]
    )
    delivered = _poll_messages(ctx, target["url"], min_count=1, timeout_s=60.0)
    assert len(delivered) >= 1, "delivery still failed at the target after granting its queue policy"
    restored_body = json.loads(delivered[0]["Body"])
    assert restored_body["detail"]["token"] == restore_token, (
        f"expected restored delivery to carry token {restore_token!r}, got {restored_body.get('detail')}"
    )


def _queue_arn(sqs, url: str) -> str:
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]


def _create_queue(ctx, suffix: str) -> dict:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name(f"sim2real-{suffix}-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"url": url, "arn": _queue_arn(sqs, url)}


def _set_queue_policy(ctx, queue: dict, rule_arn: str) -> None:
    sqs = ctx.client("sqs")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridgeRule",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue["arn"],
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)})


def _create_rule(ctx, suffix: str, pattern: dict) -> dict:
    events = ctx.client("events")
    name = ctx.unique_name(f"sim2real-{suffix}-")
    resp = events.put_rule(Name=name, EventPattern=json.dumps(pattern), State="ENABLED")
    ctx.on_cleanup(lambda: events.delete_rule(Name=name))
    events.tag_resource(ResourceARN=resp["RuleArn"], Tags=[{"Key": "sim2real", "Value": CHECK}])
    return {"name": name, "arn": resp["RuleArn"]}


def _put_target(ctx, rule_name: str, target_id: str, queue_arn: str, **extra) -> None:
    events = ctx.client("events")
    target = {"Id": target_id, "Arn": queue_arn, **extra}
    events.put_targets(Rule=rule_name, Targets=[target])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=[target_id]))


def _poll_messages(ctx, queue_url: str, min_count: int = 1, timeout_s: float = 90.0):
    sqs = ctx.client("sqs")
    out = []
    deadline = time.monotonic() + timeout_s
    while len(out) < min_count and time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5, MessageAttributeNames=["All"]
        )
        for m in resp.get("Messages", []):
            out.append(m)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return out


def _assert_absent(ctx, queue_url: str, timeout_s: float = 40.0) -> None:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    leaked = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            leaked.append(m)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
        if leaked:
            break
    if leaked:
        raise AssertionError(f"expected no message on the policy-less target, got {len(leaked)}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
