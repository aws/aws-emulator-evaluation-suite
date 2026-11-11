"""eventbridge-missing-queue-policy-blocks-delivery."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-missing-queue-policy-blocks-delivery"
GROUP = "overly-permissive"
SERVICES = ["mediaconnect"]


@tags("axis:negative-delivery", "cap:c7", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """One EventBridge rule sends a MediaConnect flow status event to two SQS queues: the queue whose
    policy grants events.amazonaws.com sqs:SendMessage for the rule receives it, while the queue without
    that policy receives nothing and reports ApproximateNumberOfMessages 0."""
    mc = ctx.client("mediaconnect")
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    flow_arn = mc.create_flow(
        Name=ctx.unique_name("sim2real-mc-flow-"),
        Source={"Name": "source1", "Protocol": "rtp", "WhitelistCidr": "203.0.113.0/24"},
    )["Flow"]["FlowArn"]
    ctx.on_cleanup(lambda: _stop_and_delete_flow(mc, flow_arn))

    allowed_queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-mc-evtok-"))[
        "QueueUrl"
    ]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=allowed_queue_url))
    allowed_queue_arn = sqs.get_queue_attributes(
        QueueUrl=allowed_queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    blocked_queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-mc-evtno-"))[
        "QueueUrl"
    ]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=blocked_queue_url))
    blocked_queue_arn = sqs.get_queue_attributes(
        QueueUrl=blocked_queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    rule_name = ctx.unique_name("sim2real-mc-rule-")
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(
            {
                "source": ["aws.mediaconnect"],
                "detail-type": ["MediaConnect Flow Status Change"],
                "resources": [flow_arn],
            }
        ),
        State="ENABLED",
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    # only the "allowed" queue gets a resource policy granting EventBridge access
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": allowed_queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=allowed_queue_url, Attributes={"Policy": json.dumps(policy)})

    events.put_targets(
        Rule=rule_name,
        Targets=[
            {"Id": "allowed-target", "Arn": allowed_queue_arn},
            {"Id": "blocked-target", "Arn": blocked_queue_arn},
        ],
    )
    ctx.on_cleanup(
        lambda: events.remove_targets(Rule=rule_name, Ids=["allowed-target", "blocked-target"])
    )

    mc.start_flow(FlowArn=flow_arn)

    positive_start = time.monotonic()
    allowed_messages = _poll_for_messages(sqs, allowed_queue_url, timeout_s=120)
    assert allowed_messages, "the properly-authorized queue never received the event"
    positive_latency_s = time.monotonic() - positive_start

    # hold the negative for at least 3x the positive control's own measured
    # delivery latency on this wiring, so a correct-but-slower target is never
    # mistaken for a blocked one
    negative_window_s = max(15.0, 3 * positive_latency_s)
    blocked_messages = _poll_for_messages(sqs, blocked_queue_url, timeout_s=negative_window_s)
    assert blocked_messages == [], (
        f"the unauthorized queue received {len(blocked_messages)} event(s) despite having no "
        f"resource policy granting EventBridge access: {blocked_messages}"
    )

    blocked_depth = sqs.get_queue_attributes(
        QueueUrl=blocked_queue_url, AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]["ApproximateNumberOfMessages"]
    assert blocked_depth == "0", (
        f"unauthorized queue's own reported depth is {blocked_depth}, expected 0 -- "
        "the independent receive-side check above disagrees with the queue's own attribute"
    )


def _poll_for_messages(sqs, queue_url: str, timeout_s: float) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            try:
                out.append(json.loads(msg["Body"]))
            except (json.JSONDecodeError, ValueError):
                pass
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        if out:
            return out
    return out


def _stop_and_delete_flow(mc, flow_arn: str) -> None:
    try:
        mc.stop_flow(FlowArn=flow_arn)
    except (mc.exceptions.BadRequestException, mc.exceptions.NotFoundException):
        pass
    for _ in range(150):
        try:
            status = mc.describe_flow(FlowArn=flow_arn)["Flow"]["Status"]
        except mc.exceptions.NotFoundException:
            return
        if status == "STANDBY":
            break
        if status == "ACTIVE":
            # A stop sent while the flow was still STARTING is refused; send it again.
            try:
                mc.stop_flow(FlowArn=flow_arn)
            except mc.exceptions.BadRequestException:
                pass
        time.sleep(2)
    try:
        mc.delete_flow(FlowArn=flow_arn)
    except mc.exceptions.NotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
