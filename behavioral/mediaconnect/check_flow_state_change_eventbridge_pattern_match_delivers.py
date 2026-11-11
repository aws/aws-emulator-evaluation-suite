"""flow-state-change-eventbridge-pattern-match-delivers."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "flow-state-change-eventbridge-pattern-match-delivers"
GROUP = "event-propagation"
SERVICES = ["mediaconnect"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Starting a flow emits a 'MediaConnect Flow Status Change' event from aws.mediaconnect that an
    EventBridge rule matching that source and detail-type delivers to its SQS queue, carrying the flow's
    ARN and currentStatus STARTING or ACTIVE."""
    mc = ctx.client("mediaconnect")
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    flow_arn = mc.create_flow(
        Name=ctx.unique_name("sim2real-mc-flow-"),
        Source={"Name": "source1", "Protocol": "rtp", "WhitelistCidr": "203.0.113.0/24"},
        FlowTags={"sim2real": CHECK},
    )["Flow"]["FlowArn"]
    ctx.on_cleanup(lambda: _stop_and_delete_flow(mc, flow_arn))

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-mc-evt-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    _grant_eventbridge_to_sqs(sqs, queue_url, queue_arn, rule_arn)
    events.put_targets(Rule=rule_name, Targets=[{"Id": "queue-target", "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["queue-target"]))

    mc.start_flow(FlowArn=flow_arn)

    messages = _poll_for_messages(sqs, queue_url, timeout_s=120)
    assert messages, "no MediaConnect flow status change event delivered to SQS"
    matched = [m for m in messages if flow_arn in m.get("resources", [])]
    assert matched, f"no delivered event referenced {flow_arn}: {messages}"
    event = matched[0]
    assert event["source"] == "aws.mediaconnect"
    assert event["detail-type"] == "MediaConnect Flow Status Change"
    assert event["detail"]["currentStatus"] in ("STARTING", "ACTIVE")


def _grant_eventbridge_to_sqs(sqs, queue_url: str, queue_arn: str, rule_arn: str) -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})


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
