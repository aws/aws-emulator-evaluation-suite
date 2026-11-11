"""deploy-cfn-events-rule-with-target-resource-lifecycle."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-events-rule-with-target-resource-lifecycle"
GROUP = "deploy"
SERVICES = ["cloudformation", "events", "sqs"]


def _template(rule_name: str, pattern: dict) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Queue": {"Type": "AWS::SQS::Queue"},
                "Rule": {
                    "Type": "AWS::Events::Rule",
                    "Properties": {
                        "Name": rule_name,
                        "EventPattern": pattern,
                        "State": "ENABLED",
                        "Targets": [
                            {"Id": "cfn-target", "Arn": {"Fn::GetAtt": ["Queue", "Arn"]}}
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
                "RuleArn": {"Value": {"Fn::GetAtt": ["Rule", "Arn"]}},
                "RuleNameGetAtt": {"Value": {"Fn::GetAtt": ["Rule", "RuleName"]}},
                "QueueArn": {"Value": {"Fn::GetAtt": ["Queue", "Arn"]}},
                "QueueUrl": {"Value": {"Ref": "Queue"}},
            },
        }
    )


@tags(
    "axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation AWS::Events::Rule with an SQS target reaches CREATE_COMPLETE,
    DescribeRule/ListTargetsByRule reflect its pattern, state, target and GetAtt
    attributes, and deleting the stack removes the rule (DescribeRule then rejects it)."""
    cfn = ctx.client("cloudformation")
    events = ctx.client("events")

    rule_name = ctx.unique_name("sim2real-behav-cfnrule-")
    source = ctx.unique_name("sim2real.behav.")
    pattern = {"source": [source]}
    stack_name = ctx.unique_name("sim2real-behav-stack-")

    cfn.create_stack(StackName=stack_name, TemplateBody=_template(rule_name, pattern))
    ctx.on_cleanup(lambda: _safe_delete_stack(cfn, stack_name))

    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    }

    rule = events.describe_rule(Name=rule_name)
    assert rule["State"] == "ENABLED", f"expected rule State ENABLED, got {rule['State']!r}"
    assert json.loads(rule["EventPattern"]) == pattern, (
        f"expected EventPattern {pattern}, got {json.loads(rule['EventPattern'])}"
    )
    assert rule["Arn"] == outputs["RuleArn"], (
        f"expected Fn::GetAtt Rule.Arn to match DescribeRule Arn {rule['Arn']!r}, got {outputs['RuleArn']!r}"
    )
    assert rule["Name"] == outputs["RuleNameGetAtt"], (
        f"expected Fn::GetAtt Rule.RuleName to match DescribeRule Name {rule['Name']!r}, "
        f"got {outputs['RuleNameGetAtt']!r}"
    )

    targets = events.list_targets_by_rule(Rule=rule_name)["Targets"]
    assert len(targets) == 1, f"expected exactly one target, got {targets!r}"
    assert targets[0]["Id"] == "cfn-target", f"expected target Id cfn-target, got {targets[0]['Id']!r}"
    assert targets[0]["Arn"] == outputs["QueueArn"], (
        f"expected target Arn to match Fn::GetAtt Queue.Arn {outputs['QueueArn']!r}, got {targets[0]['Arn']!r}"
    )

    sqs = ctx.client("sqs")
    queue_url = outputs["QueueUrl"]
    policy = json.loads(
        sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["Policy"])["Attributes"]["Policy"]
    )
    statements = [(st.get("Sid"), st.get("Principal"), st.get("Action")) for st in policy["Statement"]]
    assert statements == [("AllowEventBridgeDelivery", {"Service": "events.amazonaws.com"}, "sqs:SendMessage")], (
        f"the QueuePolicy on the target queue reads back as {policy!r}"
    )

    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    got = _error(lambda: sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["Policy"]))
    assert got == ("AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist."), (
        f"the stack's target queue (and the QueuePolicy on it) after the stack delete: {got!r}"
    )

    code, message = _error(lambda: events.describe_rule(Name=rule_name))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading the rule after its owning stack was "
        f"deleted, got {code!r}: {message!r}"
    )
    assert message == f"Rule {rule_name} does not exist on EventBus default.", (
        f"unexpected not-found message {message!r}"
    )


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _safe_delete_stack(cfn, stack_name: str) -> None:
    try:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
