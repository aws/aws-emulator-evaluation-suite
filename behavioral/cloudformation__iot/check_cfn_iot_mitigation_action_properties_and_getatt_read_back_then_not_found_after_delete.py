"""cfn-iot-mitigation-action-properties-and-getatt-read-back-then-not-found-after-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-iot-mitigation-action-properties-and-getatt-read-back-then-not-found-after-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "iot"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def until_raises(fn, timeout_s=90.0):
    """Poll ``fn()`` every 2 s until it raises a ClientError (an eventually consistent delete).

    Grade the error afterwards with expect_error; a success past the deadline fails.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"still answering after {timeout_s:.0f}s: {result!r}")
        time.sleep(2)


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

@tags("axis:happy-path", "cap:c7", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::IoT::MitigationAction is real at IoT: Ref equals the
    action name, every Fn::GetAtt attribute and the declared properties match IoT's own
    describe_mitigation_action, and deleting the stack removes it from IoT, not just from CFN."""
    cfn = ctx.client("cloudformation")
    iot = ctx.client("iot")

    stack_name = ctx.unique_name("sim2real-behav-cfn-mit-")
    action_name = ctx.unique_name("sim2real-behav-mit-")

    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "iot.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    template = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic"},
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": trust,
                    "Policies": [{
                        "PolicyName": "sim2real-publish",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": "sns:Publish",
                                "Resource": {"Ref": "Topic"},
                            }],
                        },
                    }],
                },
            },
            "MitigationAction": {
                "Type": "AWS::IoT::MitigationAction",
                "Properties": {
                    "ActionName": action_name,
                    "RoleArn": {"Fn::GetAtt": ["Role", "Arn"]},
                    "ActionParams": {
                        "PublishFindingToSnsParams": {"TopicArn": {"Ref": "Topic"}},
                    },
                },
            },
        },
        "Outputs": {
            "ActionRef": {"Value": {"Ref": "MitigationAction"}},
            "ActionArn": {"Value": {"Fn::GetAtt": ["MitigationAction", "MitigationActionArn"]}},
            "ActionId": {"Value": {"Fn::GetAtt": ["MitigationAction", "MitigationActionId"]}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
            "TopicArn": {"Value": {"Ref": "Topic"}},
        },
    })

    stack_id = create_stack(ctx, cfn, stack_name, template, Capabilities=["CAPABILITY_IAM"])
    created = wait_stack(cfn, stack_id, timeout_s=240.0)
    assert created == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {created!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )

    outputs = stack_outputs(cfn, stack_id)
    assert outputs["ActionRef"] == action_name, (
        f"Ref MitigationAction was {outputs['ActionRef']!r}, expected the primary identifier "
        f"{action_name!r}"
    )

    # Independent read at the destination: IoT's own action record must carry the properties
    # the template declared, and the GetAtt outputs must match IoT's own answer.
    action = iot.describe_mitigation_action(actionName=action_name)
    assert action["actionArn"] == outputs["ActionArn"], (
        f"GetAtt MitigationAction.MitigationActionArn was {outputs['ActionArn']!r}, "
        f"IoT's own actionArn is {action['actionArn']!r}"
    )
    assert action["actionId"] == outputs["ActionId"], (
        f"GetAtt MitigationAction.MitigationActionId was {outputs['ActionId']!r}, "
        f"IoT's own actionId is {action['actionId']!r}"
    )
    assert action["roleArn"] == outputs["RoleArn"], (
        f"expected roleArn {outputs['RoleArn']!r}, got {action['roleArn']!r}"
    )
    assert action["actionParams"]["publishFindingToSnsParams"]["topicArn"] == outputs["TopicArn"], (
        f"expected ActionParams.PublishFindingToSnsParams.TopicArn {outputs['TopicArn']!r}, "
        f"got {action['actionParams']['publishFindingToSnsParams']['topicArn']!r}"
    )

    delete_stack(cfn, stack_id)

    # The physical delete may lag DELETE_COMPLETE: poll to the refusal, then grade it.
    action_gone = ("ResourceNotFoundException", f"No action with name {action_name} is found")
    until_raises(lambda: iot.describe_mitigation_action(actionName=action_name), timeout_s=60.0)
    expect_error(lambda: iot.describe_mitigation_action(actionName=action_name), *action_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
