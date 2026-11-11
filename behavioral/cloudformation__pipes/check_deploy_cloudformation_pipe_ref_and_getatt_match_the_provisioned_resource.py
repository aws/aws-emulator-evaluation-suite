"""deploy-cloudformation-pipe-ref-and-getatt-match-the-provisioned-resource."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cloudformation-pipe-ref-and-getatt-match-the-provisioned-resource"
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

_DESCRIPTION = "sim2real cloudformation pipe provisioning check"


def _template(pipe_name: str) -> dict:
    tags = [{"Key": "sim2real-pipe", "Value": CHECK}]
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
            "ThePipe": {
                "Type": "AWS::Pipes::Pipe",
                "Properties": {
                    "Name": pipe_name,
                    "Description": _DESCRIPTION,
                    "RoleArn": {"Fn::GetAtt": ["PipeRole", "Arn"]},
                    "Source": {"Fn::GetAtt": ["SourceQueue", "Arn"]},
                    "SourceParameters": {"SqsQueueParameters": {"BatchSize": 1}},
                    "Target": {"Fn::GetAtt": ["TargetQueue", "Arn"]},
                    "DesiredState": "STOPPED",
                    "Tags": {"sim2real-pipe": CHECK},
                },
            },
        },
        "Outputs": {
            "PipeRef": {"Value": {"Ref": "ThePipe"}},
            "PipeArn": {"Value": {"Fn::GetAtt": ["ThePipe", "Arn"]}},
            "PipeCurrentState": {"Value": {"Fn::GetAtt": ["ThePipe", "CurrentState"]}},
            "PipeRoleArn": {"Value": {"Fn::GetAtt": ["PipeRole", "Arn"]}},
            "SourceQueueArn": {"Value": {"Fn::GetAtt": ["SourceQueue", "Arn"]}},
            "TargetQueueArn": {"Value": {"Fn::GetAtt": ["TargetQueue", "Arn"]}},
        },
    }


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A stack's AWS::Pipes::Pipe reaches CREATE_COMPLETE and Pipes itself holds the resource:
    Ref is the pipe's Name, every GetAtt output matches DescribePipe, and the template's own
    properties read back unchanged. Deleting the stack removes the pipe from Pipes too.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-pipes-pipe.html
    """
    cf = ctx.client("cloudformation")
    pipes = ctx.client("pipes")

    pipe_name = ctx.unique_name("sim2real-cfn-pipe-")
    stack_name = ctx.unique_name("sim2real-cfn-pipe-stack-")
    template = _template(pipe_name)

    stack_id = create_stack(ctx, cf, stack_name, json.dumps(template),
                            Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"the stack ended {status!r}, expected CREATE_COMPLETE: "
        f"{decisive_rows(stack_events(cf, stack_id))!r}"
    )

    outputs = stack_outputs(cf, stack_id)
    assert outputs["PipeRef"] == pipe_name, (
        f"Ref must equal the pipe's primary identifier, the template's Name {pipe_name!r}; "
        f"Ref was {outputs['PipeRef']!r}"
    )
    listed = [(p["Name"], p["Arn"]) for p in paginate(pipes, "list_pipes", "Pipes", NamePrefix=pipe_name)
              if p["Name"] == pipe_name]
    assert listed == [(pipe_name, outputs["PipeArn"])], (
        f"ListPipes entries named {pipe_name!r} were {listed!r}, expected one with GetAtt Arn "
        f"{outputs['PipeArn']!r}"
    )
    described = pipes.describe_pipe(Name=pipe_name)
    assert described["Arn"] == outputs["PipeArn"], (
        f"GetAtt Arn was {outputs['PipeArn']!r}, DescribePipe Arn was {described['Arn']!r}"
    )
    assert described["CurrentState"] == outputs["PipeCurrentState"], (
        f"GetAtt CurrentState was {outputs['PipeCurrentState']!r}, "
        f"DescribePipe CurrentState was {described['CurrentState']!r}"
    )
    assert described["CurrentState"] == "STOPPED", (
        f"the template set DesiredState=STOPPED; DescribePipe CurrentState was "
        f"{described['CurrentState']!r}"
    )
    assert described["RoleArn"] == outputs["PipeRoleArn"], (
        f"the template's RoleArn property must read back unchanged; template set "
        f"{outputs['PipeRoleArn']!r}, DescribePipe RoleArn was {described['RoleArn']!r}"
    )
    assert described["Source"] == outputs["SourceQueueArn"], (
        f"the template's Source property must read back unchanged; template set "
        f"{outputs['SourceQueueArn']!r}, DescribePipe Source was {described['Source']!r}"
    )
    assert described["Target"] == outputs["TargetQueueArn"], (
        f"the template's Target property must read back unchanged; template set "
        f"{outputs['TargetQueueArn']!r}, DescribePipe Target was {described['Target']!r}"
    )
    assert described["Description"] == _DESCRIPTION, (
        f"the template's Description property must read back unchanged; template set "
        f"{_DESCRIPTION!r}, DescribePipe Description was {described['Description']!r}"
    )
    got = (
        described["SourceParameters"]["SqsQueueParameters"]["BatchSize"],
        described["DesiredState"],
        described.get("Tags"),
    )
    # The template's tag, the propagated stack tag and the aws:cloudformation:* tags.
    want_tags = {"sim2real-pipe": CHECK, "sim2real": stack_name,
                 "aws:cloudformation:stack-name": stack_name,
                 "aws:cloudformation:logical-id": "ThePipe",
                 "aws:cloudformation:stack-id": stack_id}
    assert got == (1, "STOPPED", want_tags), (
        f"DescribePipe BatchSize/DesiredState/Tags were {got!r}, expected the template's "
        f"{(1, 'STOPPED', want_tags)!r}"
    )

    delete_stack(cf, stack_id)

    # After the stack is deleted, Pipes must no longer have the resource.
    pipe_not_found = ("NotFoundException", f"Pipe {pipe_name} does not exist.")
    expect_error(lambda: pipes.describe_pipe(Name=pipe_name), *pipe_not_found)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
