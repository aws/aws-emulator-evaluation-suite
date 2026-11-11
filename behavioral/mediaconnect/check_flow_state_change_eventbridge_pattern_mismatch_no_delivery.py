"""flow-state-change-eventbridge-pattern-mismatch-no-delivery."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "flow-state-change-eventbridge-pattern-mismatch-no-delivery"
GROUP = "event-propagation"
SERVICES = ["mediaconnect"]


@tags("axis:negative-delivery", "cap:c1", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule whose pattern names a detail-type MediaConnect never emits delivers nothing to its SQS queue
    when the flow starts, while a rule matching 'MediaConnect Flow Status Change' delivers the same
    transition to its queue."""
    mc = ctx.client("mediaconnect")
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    flow_arn = mc.create_flow(
        Name=ctx.unique_name("sim2real-mc-flow-"),
        Source={"Name": "source1", "Protocol": "rtp", "WhitelistCidr": "203.0.113.0/24"},
        FlowTags={"sim2real:managed": "true"},
    )["Flow"]["FlowArn"]
    ctx.on_cleanup(lambda: _stop_and_delete_flow(mc, flow_arn))

    mismatch_queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-mc-evtmiss-"),
        tags={"sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=mismatch_queue_url))
    mismatch_queue_arn = sqs.get_queue_attributes(
        QueueUrl=mismatch_queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    match_queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-mc-evtmatch-"),
        tags={"sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=match_queue_url))
    match_queue_arn = sqs.get_queue_attributes(QueueUrl=match_queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    mismatch_rule_name = ctx.unique_name("sim2real-mc-rule-miss-")
    mismatch_rule_arn = events.put_rule(
        Name=mismatch_rule_name,
        EventPattern=json.dumps(
            {
                "source": ["aws.mediaconnect"],
                "detail-type": ["MediaConnect Flow Alert"],
                "resources": [flow_arn],
            }
        ),
        State="ENABLED",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=mismatch_rule_name))
    _grant_eventbridge_to_sqs(sqs, mismatch_queue_url, mismatch_queue_arn, mismatch_rule_arn)
    events.put_targets(
        Rule=mismatch_rule_name, Targets=[{"Id": "queue-target", "Arn": mismatch_queue_arn}]
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=mismatch_rule_name, Ids=["queue-target"]))

    match_rule_name = ctx.unique_name("sim2real-mc-rule-match-")
    match_rule_arn = events.put_rule(
        Name=match_rule_name,
        EventPattern=json.dumps(
            {
                "source": ["aws.mediaconnect"],
                "detail-type": ["MediaConnect Flow Status Change"],
                "resources": [flow_arn],
            }
        ),
        State="ENABLED",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=match_rule_name))
    _grant_eventbridge_to_sqs(sqs, match_queue_url, match_queue_arn, match_rule_arn)
    events.put_targets(Rule=match_rule_name, Targets=[{"Id": "queue-target", "Arn": match_queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=match_rule_name, Ids=["queue-target"]))

    mc.start_flow(FlowArn=flow_arn)

    # positive control: the matching-pattern rule's queue receives the event
    matched_messages = _poll_for_messages(sqs, match_queue_url, timeout_s=120)
    assert matched_messages, "matching-pattern rule never delivered the event (setup is broken)"

    # the mismatched-pattern rule's queue receives nothing, polled after the matching
    # rule's queue has already received the same transition
    mismatched_messages = _poll_for_messages(sqs, mismatch_queue_url, timeout_s=20)
    assert mismatched_messages == [], (
        f"mismatched-pattern rule's queue received event(s) it should never match: "
        f"{mismatched_messages}"
    )


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
