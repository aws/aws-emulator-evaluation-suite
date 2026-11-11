"""deploy-topic-rule-cfn-routes-message."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-topic-rule-cfn-routes-message"
GROUP = "deploy"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed AWS::IoT::TopicRule matches its SQL filter and forwards a
    published MQTT message to the configured SQS action -- and does NOT forward
    a message published to a topic the rule's SQL does not select.
    """
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    iot_data = ctx.client("iot-data")

    rule_name = ctx.unique_name("sim2real_topicrule_").replace("-", "_")
    match_topic = ctx.unique_name("sim2real-topicrule-") + "/match"
    mismatch_topic = ctx.unique_name("sim2real-topicrule-") + "/other"
    rule_sql = f"SELECT * FROM '{match_topic}'"
    stack_name = ctx.unique_name("sim2real-topicrule-stack-")

    template = _topic_rule_template()
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Parameters=[
            {"ParameterKey": "RuleName", "ParameterValue": rule_name},
            {"ParameterKey": "RuleSql", "ParameterValue": rule_sql},
        ],
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    }
    queue_url = outputs["QueueUrl"]

    match_marker = ctx.unique_name("match-marker-")
    mismatch_marker = ctx.unique_name("mismatch-marker-")

    iot_data.publish(
        topic=match_topic,
        payload=json.dumps({"marker": match_marker}).encode("utf-8"),
        qos=0,
    )
    iot_data.publish(
        topic=mismatch_topic,
        payload=json.dumps({"marker": mismatch_marker}).encode("utf-8"),
        qos=0,
    )

    found_markers = _poll_sqs_markers(sqs, queue_url, {match_marker, mismatch_marker}, timeout_s=45)

    assert match_marker in found_markers, "matching message was never routed to the SQS action"
    assert mismatch_marker not in found_markers, (
        "message published to a non-matching topic was incorrectly routed by the rule's SQL filter"
    )


def _topic_rule_template() -> dict:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "RuleName": {"Type": "String"},
            "RuleSql": {"Type": "String"},
        },
        "Resources": {
            "Queue": {"Type": "AWS::SQS::Queue"},
            "TopicRuleRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "iot.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "SendToQueue",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "sqs:SendMessage",
                                        "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "Rule": {
                "Type": "AWS::IoT::TopicRule",
                "DependsOn": "TopicRuleRole",
                "Properties": {
                    "RuleName": {"Ref": "RuleName"},
                    "TopicRulePayload": {
                        "Sql": {"Ref": "RuleSql"},
                        "RuleDisabled": False,
                        "Actions": [
                            {
                                "Sqs": {
                                    "QueueUrl": {"Ref": "Queue"},
                                    "RoleArn": {"Fn::GetAtt": ["TopicRuleRole", "Arn"]},
                                    "UseBase64": False,
                                }
                            }
                        ],
                    },
                },
            },
        },
        "Outputs": {
            "QueueUrl": {"Value": {"Ref": "Queue"}},
        },
    }


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


def _poll_sqs_markers(sqs, queue_url: str, wanted: set, timeout_s: float = 45.0) -> set:
    found: set = set()
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and not wanted.issubset(found) and len(found) < len(wanted):
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (ValueError, TypeError):
                body = {}
            marker = body.get("marker") if isinstance(body, dict) else None
            if marker:
                found.add(marker)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        if found:
            # give the (deliberately absent) mismatch a brief further chance before
            # declaring victory, since delivery is asynchronous and at-least-once.
            time.sleep(1)
    return found


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
