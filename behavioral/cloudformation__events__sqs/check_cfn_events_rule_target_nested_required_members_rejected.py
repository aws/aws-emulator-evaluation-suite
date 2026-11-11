"""cfn-events-rule-target-nested-required-members-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-events-rule-target-nested-required-members-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "events", "sqs"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}


def _good_template(rule_name: str) -> str:
    return json.dumps({
        "Resources": {
            "Queue": {"Type": "AWS::SQS::Queue"},
            "Rule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "Name": rule_name,
                    "EventPattern": {"source": [rule_name]},
                    "Targets": [{"Id": "cfn-target", "Arn": {"Fn::GetAtt": ["Queue", "Arn"]}}],
                },
            },
            "QueuePolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "Queue"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Sid": "AllowEventBridgeDelivery", "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"}, "Action": "sqs:SendMessage",
                            "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
                            "Condition": {"ArnEquals": {"aws:SourceArn": {"Fn::GetAtt": ["Rule", "Arn"]}}},
                        }],
                    },
                },
            },
        },
    })


def _bad_template(rule_name: str, target: dict) -> str:
    return json.dumps({
        "Resources": {
            "Rule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "Name": rule_name,
                    "EventPattern": {"source": [rule_name]},
                    "Targets": [target],
                },
            },
        },
    })


def _wait_terminal(cfn, name: str, timeout_s: float = 180.0) -> str:
    """Poll DescribeStacks until the stack reaches a terminal status; return it."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {name} did not reach a terminal state within {timeout_s}s (last={last!r})")


def _validation_errors(cfn, name: str) -> list[tuple]:
    """``(status, mode, reason, path)`` of each VALIDATION_ERROR operation event for Rule, sorted."""
    out: list[tuple] = []
    kwargs = {"StackName": name}
    while True:
        page = cfn.describe_events(**kwargs)
        out.extend(
            (e.get("ValidationStatus"), e.get("ValidationFailureMode"),
             e.get("ValidationStatusReason"), e.get("ValidationPath"))
            for e in page["OperationEvents"]
            if e.get("EventType") == "VALIDATION_ERROR" and e.get("LogicalResourceId") == "Rule"
        )
        if not page.get("NextToken"):
            return sorted(out)
        kwargs["NextToken"] = page["NextToken"]


def _delete_stack(cfn, name: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cfn.delete_stack(StackName=name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A rule target's EcsParameters, BatchParameters, AppSyncParameters or AwsVpcConfiguration
    missing a required nested member fails pre-provisioning property validation with the exact
    reason and creates no rule; the conforming rule with a plain target deploys.
    """
    cfn = ctx.client("cloudformation")
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    good_rule = ctx.unique_name("sim2real-behav-evttgt-ok-")
    good_stack = ctx.unique_name("sim2real-behav-evttgt-ok-stack-")
    good_stack_id = cfn.create_stack(StackName=good_stack, TemplateBody=_good_template(good_rule))["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, good_stack))
    status = _wait_terminal(cfn, good_stack)
    assert status == "CREATE_COMPLETE", f"control stack: expected CREATE_COMPLETE, got {status!r}"
    queue_url = cfn.describe_stack_resource(
        StackName=good_stack, LogicalResourceId="Queue",
    )["StackResourceDetail"]["PhysicalResourceId"]
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"],
    )["Attributes"]["QueueArn"]
    targets = events.list_targets_by_rule(Rule=good_rule)["Targets"]
    pairs = [(t["Id"], t["Arn"]) for t in targets]
    assert pairs == [("cfn-target", queue_arn)], (
        f"control rule's targets read back as {targets!r}, expected the one target on the stack's queue"
    )
    arn_prefix = f"arn:{good_stack_id.split(':')[1]}:"

    cases = [
        ("EcsParameters missing TaskDefinitionArn",
         {"Id": "t1", "Arn": arn_prefix + "ecs:" + ctx.region + ":" + ctx.account + ":cluster/dummy",
          "EcsParameters": {"TaskCount": 1}},
         [("FAILED", "FAIL", "Required property [TaskDefinitionArn] not found",
           "/Resources/Rule/Properties/Targets/0/EcsParameters")]),
        ("BatchParameters missing JobName and JobDefinition",
         {"Id": "t1", "Arn": arn_prefix + "batch:" + ctx.region + ":" + ctx.account + ":job-queue/dummy",
          "BatchParameters": {}},
         sorted([
             ("FAILED", "FAIL", "Required property [JobDefinition] not found",
              "/Resources/Rule/Properties/Targets/0/BatchParameters"),
             ("FAILED", "FAIL", "Required property [JobName] not found",
              "/Resources/Rule/Properties/Targets/0/BatchParameters"),
         ])),
        ("AppSyncParameters missing GraphQLOperation",
         {"Id": "t1", "Arn": arn_prefix + "appsync:" + ctx.region + ":" + ctx.account + ":apis/dummy",
          "AppSyncParameters": {}},
         [("FAILED", "FAIL", "Required property [GraphQLOperation] not found",
           "/Resources/Rule/Properties/Targets/0/AppSyncParameters")]),
        ("EcsParameters AwsVpcConfiguration missing Subnets",
         {"Id": "t1", "Arn": arn_prefix + "ecs:" + ctx.region + ":" + ctx.account + ":cluster/dummy",
          "EcsParameters": {
              "TaskDefinitionArn": arn_prefix + "ecs:" + ctx.region + ":" + ctx.account + ":task-definition/dummy",
              "NetworkConfiguration": {"AwsVpcConfiguration": {}},
          }},
         [("FAILED", "FAIL", "Required property [Subnets] not found",
           "/Resources/Rule/Properties/Targets/0/EcsParameters/NetworkConfiguration/AwsVpcConfiguration")]),
    ]
    for label, target, want in cases:
        bad_rule = ctx.unique_name(f"sim2real-behav-evttgt-bad-{len(label)}-")
        bad_stack = ctx.unique_name(f"sim2real-behav-evttgt-bad-{len(label)}-stack-")
        cfn.create_stack(StackName=bad_stack, TemplateBody=_bad_template(bad_rule, target))
        ctx.on_cleanup(lambda bad_stack=bad_stack: _delete_stack(cfn, bad_stack))
        status = _wait_terminal(cfn, bad_stack)
        assert status == "ROLLBACK_COMPLETE", f"{label}: expected ROLLBACK_COMPLETE, got {status!r}"
        found = _validation_errors(cfn, bad_stack)
        assert found == want, f"{label}: validation errors expected {want!r}, got {found!r}"
        resources = cfn.list_stack_resources(StackName=bad_stack)["StackResourceSummaries"]
        assert resources == [], (
            f"{label}: a stack rejected before provisioning must list no resources, got {resources!r}"
        )
        got = _error(lambda bad_rule=bad_rule: events.describe_rule(Name=bad_rule))
        assert got == ("ResourceNotFoundException", f"Rule {bad_rule} does not exist on EventBus default."), (
            f"{label}: DescribeRule on the never-created rule: {got!r}"
        )

    # Control survives all the rejections above.
    still = events.list_targets_by_rule(Rule=good_rule)["Targets"]
    still_pairs = [(t["Id"], t["Arn"]) for t in still]
    assert still_pairs == [("cfn-target", queue_arn)], f"control rule's targets changed to {still!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
