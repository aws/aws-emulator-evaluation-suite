"""deploy-eventbus-rule-target-cfn-then-put-events-delivers."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-eventbus-rule-target-cfn-then-put-events-delivers"
GROUP = "deploy"
SERVICES = ["events"]

_MANAGED_TAG_KEY = "sim2real:managed"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation stack with a custom EventBus, Rule and SQS target reaches CREATE_COMPLETE,
    and PutEvents on the deployed bus is routed to the deployed queue per the rule's pattern."""
    cfn = ctx.client("cloudformation")
    events = ctx.client("events")

    stack_name = ctx.unique_name("sim2real-evb-stack-")
    bus_name = ctx.unique_name("sim2real-evb-bus-")
    queue_name = ctx.unique_name("sim2real-evb-cfnq-")
    rule_name = ctx.unique_name("sim2real-evb-cfnrule-")
    source = ctx.unique_name("sim2real.cfn.")
    detail_type = "sim2real-cfn-matched-type"

    template = _build_template(bus_name, queue_name, rule_name, source, detail_type)
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Tags=[{"Key": _MANAGED_TAG_KEY, "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name))

    status = _wait_for_stack_status(
        ctx, stack_name, {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"}, timeout_s=180.0
    )
    assert status == "CREATE_COMPLETE", f"stack {stack_name} ended in unexpected status {status}"

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    }
    queue_url = outputs["QueueUrl"]

    rule = events.describe_rule(Name=rule_name, EventBusName=bus_name)
    assert rule["State"] == "ENABLED", f"expected rule {rule_name} State=ENABLED, got {rule['State']!r}"
    actual_pattern = json.loads(rule["EventPattern"])
    expected_pattern = {"source": [source], "detail-type": [detail_type]}
    assert actual_pattern == expected_pattern, (
        f"expected rule {rule_name} EventPattern {expected_pattern}, got {actual_pattern}"
    )

    targets = events.list_targets_by_rule(Rule=rule_name, EventBusName=bus_name)["Targets"]
    assert any(t["Id"] == "cfn-queue-target" for t in targets), "deployed rule has no target wired"

    marker = ctx.unique_name("marker-")
    events.put_events(
        Entries=[
            {
                "EventBusName": bus_name,
                "Source": source,
                "DetailType": detail_type,
                "Detail": json.dumps({"marker": marker}),
            }
        ]
    )

    envelope = _poll_for_marker(ctx, queue_url, marker, timeout_s=90.0)
    assert envelope["source"] == source, f"expected delivered envelope source {source!r}, got {envelope['source']!r}"
    assert envelope["detail-type"] == detail_type, (
        f"expected delivered envelope detail-type {detail_type!r}, got {envelope['detail-type']!r}"
    )
    assert envelope["detail"]["marker"] == marker, (
        f"expected delivered envelope detail.marker {marker!r}, got {envelope['detail'].get('marker')!r}"
    )


def _build_template(bus_name: str, queue_name: str, rule_name: str, source: str, detail_type: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Bus": {
                    "Type": "AWS::Events::EventBus",
                    "Properties": {"Name": bus_name},
                },
                "Queue": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {"QueueName": queue_name},
                },
                "Rule": {
                    "Type": "AWS::Events::Rule",
                    "Properties": {
                        "Name": rule_name,
                        # Ref on AWS::Events::EventBus returns the event bus Name.
                        "EventBusName": {"Ref": "Bus"},
                        "EventPattern": {"source": [source], "detail-type": [detail_type]},
                        "State": "ENABLED",
                        "Targets": [
                            {"Id": "cfn-queue-target", "Arn": {"Fn::GetAtt": ["Queue", "Arn"]}}
                        ],
                    },
                },
                "QueuePolicy": {
                    "Type": "AWS::SQS::QueuePolicy",
                    "Properties": {
                        "Queues": [{"Ref": "Queue"}],
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Sid": "AllowEventBridgeDelivery",
                                    "Effect": "Allow",
                                    "Principal": {"Service": "events.amazonaws.com"},
                                    "Action": "sqs:SendMessage",
                                    "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
                                    "Condition": {
                                        "ArnEquals": {"aws:SourceArn": {"Fn::GetAtt": ["Rule", "Arn"]}}
                                    },
                                }
                            ],
                        },
                    },
                },
            },
            "Outputs": {
                "QueueUrl": {"Value": {"Ref": "Queue"}},
                "QueueArn": {"Value": {"Fn::GetAtt": ["Queue", "Arn"]}},
            },
        }
    )


def _wait_for_stack_status(
    ctx, stack_name: str, terminal_statuses: set[str], timeout_s: float = 180.0, interval_s: float = 5.0
) -> str:
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in terminal_statuses:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach a terminal status within {timeout_s}s (last={status})")


def _delete_stack_and_wait(ctx, stack_name: str, timeout_s: float = 180.0, interval_s: float = 5.0) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if "does not exist" in str(exc):
                return
            raise
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} teardown ended in DELETE_FAILED")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach DELETE_COMPLETE within {timeout_s}s (last={status})")


def _poll_for_marker(ctx, queue_url: str, marker: str, timeout_s: float = 90.0) -> dict:
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
