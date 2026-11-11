"""deploy-cloudformation-pipe-missing-target-property-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cloudformation-pipe-missing-target-property-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "pipes"]

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


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


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

_EXPECTED_VALIDATION_ROW = (
    "ThePipe", "PROPERTY_VALIDATION", "FAILED", "FAIL",
    "Required property [Target] not found", "/Resources/ThePipe/Properties",
)


def _template(pipe_name: str, *, include_target: bool) -> dict:
    tags = [{"Key": "sim2real-pipe", "Value": CHECK}]
    pipe_properties = {
        "Name": pipe_name,
        "RoleArn": {"Fn::GetAtt": ["PipeRole", "Arn"]},
        "Source": {"Fn::GetAtt": ["SourceQueue", "Arn"]},
        "SourceParameters": {"SqsQueueParameters": {"BatchSize": 1}},
        "DesiredState": "STOPPED",
        "Tags": {"sim2real-pipe": CHECK},
    }
    if include_target:
        pipe_properties["Target"] = {"Fn::GetAtt": ["TargetQueue", "Arn"]}
    return {
        "Resources": {
            "SourceQueue": {"Type": "AWS::SQS::Queue", "Properties": {"Tags": tags}},
            "TargetQueue": {"Type": "AWS::SQS::Queue", "Properties": {"Tags": tags}},
            "PipeRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "pipes.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                    "Policies": [{
                        "PolicyName": "pipe-sqs-access",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                                    "Resource": {"Fn::GetAtt": ["SourceQueue", "Arn"]},
                                },
                                {
                                    "Effect": "Allow",
                                    "Action": ["sqs:SendMessage"],
                                    "Resource": {"Fn::GetAtt": ["TargetQueue", "Arn"]},
                                },
                            ],
                        },
                    }],
                    "Tags": tags,
                },
            },
            "ThePipe": {"Type": "AWS::Pipes::Pipe", "Properties": pipe_properties},
        },
        "Outputs": {
            "SourceQueueArn": {"Value": {"Fn::GetAtt": ["SourceQueue", "Arn"]}},
            "TargetQueueArn": {"Value": {"Fn::GetAtt": ["TargetQueue", "Arn"]}},
            "PipeRoleArn": {"Value": {"Fn::GetAtt": ["PipeRole", "Arn"]}},
        },
    }


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A stack whose AWS::Pipes::Pipe omits the schema-required Target property is rejected
    with the exact schema-validation reason, and Pipes never holds such a resource; a sibling
    stack that is identical except for a present Target deploys and reads back.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-pipes-pipe.html
    """
    cf = ctx.client("cloudformation")
    pipes = ctx.client("pipes")

    bad_name = ctx.unique_name("sim2real-cfn-pipe-")
    good_name = ctx.unique_name("sim2real-cfn-pipe-")

    bad_id = create_stack(ctx, cf, ctx.unique_name("sim2real-cfn-pipe-bad-"),
                          json.dumps(_template(bad_name, include_target=False)),
                          Capabilities=["CAPABILITY_IAM"])
    good_stack = ctx.unique_name("sim2real-cfn-pipe-good-")
    good_id = create_stack(ctx, cf, good_stack, json.dumps(_template(good_name, include_target=True)),
                           Capabilities=["CAPABILITY_IAM"])

    bad_status = wait_stack(cf, bad_id)
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"a stack whose Pipe omits the required Target property ended {bad_status!r}, "
        f"expected ROLLBACK_COMPLETE"
    )
    errors = [r for r in validation_rows(cf, bad_id) if r[0] == "ThePipe"]
    assert errors == [_EXPECTED_VALIDATION_ROW], (
        f"ThePipe's pre-deployment validation errors were {errors!r}, "
        f"expected [{_EXPECTED_VALIDATION_ROW!r}]"
    )

    # The rejected template must never have created a pipe.
    bad_not_found = ("NotFoundException", f"Pipe {bad_name} does not exist.")
    expect_error(lambda: pipes.describe_pipe(Name=bad_name), *bad_not_found)

    good_status = wait_stack(cf, good_id)
    assert good_status == "CREATE_COMPLETE", (
        f"the positive control ended {good_status!r}: {decisive_rows(stack_events(cf, good_id))!r}"
    )
    outputs = stack_outputs(cf, good_id)
    described = pipes.describe_pipe(Name=good_name)
    got = (described["Name"], described["Target"], described["Source"], described["RoleArn"])
    want = (good_name, outputs["TargetQueueArn"], outputs["SourceQueueArn"], outputs["PipeRoleArn"])
    assert got == want, f"positive control DescribePipe Name/Target/Source/RoleArn were {got!r}, expected {want!r}"
    got = (
        described["DesiredState"],
        described["CurrentState"],
        described["SourceParameters"]["SqsQueueParameters"]["BatchSize"],
        described.get("Tags"),
    )
    # The template's tag, the propagated stack tag and the aws:cloudformation:* tags.
    want_tags = {"sim2real-pipe": CHECK, "sim2real": good_stack,
                 "aws:cloudformation:stack-name": good_stack,
                 "aws:cloudformation:logical-id": "ThePipe",
                 "aws:cloudformation:stack-id": good_id}
    want = ("STOPPED", "STOPPED", 1, want_tags)
    assert got == want, (
        f"positive control DesiredState/CurrentState/BatchSize/Tags were {got!r}, expected {want!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
