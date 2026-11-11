"""wait-condition-and-creation-policy-timeout-reasons."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "wait-condition-and-creation-policy-timeout-reasons"
GROUP = "wait-conditions"
SERVICES = ["cloudformation"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

_CLASSIC_TEMPLATE = json.dumps({
    "Resources": {
        "Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
        "ClassicWait": {
            "Type": "AWS::CloudFormation::WaitCondition",
            "Properties": {"Handle": {"Ref": "Handle"}, "Timeout": "60", "Count": 1},
        },
    },
})
_POLICY_TEMPLATE = json.dumps({
    "Resources": {
        "PolicyWait": {
            "Type": "AWS::CloudFormation::WaitCondition",
            "CreationPolicy": {"ResourceSignal": {"Timeout": "PT1M", "Count": 1}},
        },
    },
})


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s so the wait fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _settle(ctx, cf, stack_id: str, *, cap_s: float = 300.0) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves *_IN_PROGRESS; return the stack."""
    deadline = time.monotonic() + _budget_s(ctx, cap_s)
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() > deadline:
            message = f"{stack_id} still {stack['StackStatus']!r} at the wait's deadline"
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget spent: {message}")
            raise AssertionError(message)
        time.sleep(3.0)


def _delete_stack(cf, stack_id: str, *, timeout_s: float = 300.0) -> None:
    """DeleteStack, then poll by StackId to DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cf.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if stack["StackStatus"] == "DELETE_COMPLETE":
            return
        if stack["StackStatus"] == "DELETE_FAILED" or time.monotonic() > deadline:
            raise AssertionError(
                f"stack {stack_id} ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}"
            )
        time.sleep(3.0)


# timing:real-time — workflow: 60 s https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-waitcondition.html
@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """A classic WaitCondition and a CreationPolicy.ResourceSignal resource, both left
    unsignaled, each fail create with their own timeout reason and the stack rolls back.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-waitcondition.html
    """
    cf = ctx.client("cloudformation")

    classic_id = cf.create_stack(
        StackName=ctx.unique_name("sim2real-behav-wct-classic-"), TemplateBody=_CLASSIC_TEMPLATE, Tags=_TAGS
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, classic_id))
    policy_id = cf.create_stack(
        StackName=ctx.unique_name("sim2real-behav-wct-policy-"), TemplateBody=_POLICY_TEMPLATE, Tags=_TAGS
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, policy_id))

    classic_final = _settle(ctx, cf, classic_id)
    policy_final = _settle(ctx, cf, policy_id)
    assert classic_final["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"an unsignaled classic WaitCondition must roll back its stack; "
        f"got {classic_final['StackStatus']!r}: {classic_final.get('StackStatusReason')!r}"
    )
    assert policy_final["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"an unsignaled CreationPolicy.ResourceSignal must roll back its stack; "
        f"got {policy_final['StackStatus']!r}: {policy_final.get('StackStatusReason')!r}"
    )

    classic_events = [e for page in cf.get_paginator("describe_stack_events").paginate(StackName=classic_id)
                      for e in page["StackEvents"]]
    classic_reasons = [
        e.get("ResourceStatusReason") for e in classic_events
        if e["LogicalResourceId"] == "ClassicWait" and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert classic_reasons == ["WaitCondition timed out. Received 0 conditions when expecting 1"], (
        f"the classic WaitCondition's failure reason differs: {classic_reasons!r}"
    )

    policy_events = [e for page in cf.get_paginator("describe_stack_events").paginate(StackName=policy_id)
                     for e in page["StackEvents"]]
    policy_reasons = [
        e.get("ResourceStatusReason") for e in policy_events
        if e["LogicalResourceId"] == "PolicyWait" and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert policy_reasons == ["Failed to receive 1 resource signal(s) within the specified duration"], (
        f"the CreationPolicy resource's failure reason differs: {policy_reasons!r}"
    )

    classic_detail = cf.describe_stack_resource(StackName=classic_id, LogicalResourceId="ClassicWait")[
        "StackResourceDetail"]
    assert classic_detail["ResourceStatus"] == "DELETE_COMPLETE", classic_detail
    policy_detail = cf.describe_stack_resource(StackName=policy_id, LogicalResourceId="PolicyWait")[
        "StackResourceDetail"]
    assert policy_detail["ResourceStatus"] == "DELETE_COMPLETE", policy_detail


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
