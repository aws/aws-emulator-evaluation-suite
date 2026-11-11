"""deploy-cfn-pipe-update-to-a-role-without-source-read-fails-and-rolls-back-to-the-working-pipe."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-cfn-pipe-update-to-a-role-without-source-read-fails-and-rolls-back-to-the-working-pipe"
GROUP = "deploy"
SERVICES = ["pipes"]

_STACK_TIMEOUT_S = 900.0
_DELIVERY_TIMEOUT_S = 120.0


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Updating a working stack's pipe to a role that cannot read its source fails the update.

    The stack reaches UPDATE_ROLLBACK_COMPLETE and the pipe is back on its original role, RUNNING,
    and still delivers records; a record delivered before the update is the positive control.
    """
    cfn = ctx.client("cloudformation")
    pipes = ctx.client("pipes")
    sqs = ctx.client("sqs")

    pipe_name = ctx.unique_name("sim2real-pipes-cfn-pipe-")
    template = _template(pipe_name)
    stack = _create_stack(ctx, cfn, ctx.unique_name("sim2real-pipes-cfn-"), template)
    status = _wait_stack(cfn, stack)
    assert status == "CREATE_COMPLETE", f"the stack ended {status!r}"
    out = _outputs(cfn, stack)
    src, tgt, good_role = out["SourceQueueUrl"], out["TargetQueueUrl"], out["GoodRoleArn"]

    before = json.dumps({"m": ctx.unique_name("before-")})
    sqs.send_message(QueueUrl=src, MessageBody=before)
    _await_record(ctx, tgt, before, timeout_s=_DELIVERY_TIMEOUT_S)

    cfn.update_stack(StackName=stack, TemplateBody=json.dumps(template),
                     Capabilities=["CAPABILITY_IAM"],
                     Parameters=[{"ParameterKey": "PipeRole", "ParameterValue": "bad"}])
    status = _wait_stack(cfn, stack)
    assert status == "UPDATE_ROLLBACK_COMPLETE", (
        f"switching the pipe to a role that cannot read its source ended {status!r}, expected "
        f"UPDATE_ROLLBACK_COMPLETE"
    )
    failures = [
        e for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack)
        for e in page["StackEvents"]
        if e["LogicalResourceId"] == "ThePipe" and e["ResourceStatus"] == "UPDATE_FAILED"
    ]
    assert len(failures) == 1, f"expected one UPDATE_FAILED event for ThePipe, got {failures!r}"
    reason = failures[0].get("ResourceStatusReason", "")
    head, sep, tail = reason.partition(" (RequestToken: ")
    expected_head = (
        "Resource handler returned message: \"Resource of type 'AWS::Pipes::Pipe' with "
        f"identifier '{pipe_name}' did not stabilize. Status Reason is Input parameter is invalid "
        "from the request due to : The provided customer role does not have permissions to call "
        "ReceiveMessage on SQS\""
    )
    assert head == expected_head and sep, (
        f"ThePipe's update failed with reason {reason!r}; expected it to start {expected_head!r}"
    )

    after = pipes.describe_pipe(Name=pipe_name)
    assert after["RoleArn"] == good_role, (
        f"the rollback must restore the original role; the pipe uses {after['RoleArn']!r}, "
        f"expected {good_role!r}"
    )
    assert after["CurrentState"] == "RUNNING", f"after the rollback the pipe is {after['CurrentState']!r}"
    later = json.dumps({"m": ctx.unique_name("after-")})
    sqs.send_message(QueueUrl=src, MessageBody=later)
    _await_record(ctx, tgt, later, timeout_s=_DELIVERY_TIMEOUT_S)



def _template(pipe_name: str) -> dict:
    """Two roles, both trusting Pipes; only GoodRole may read the source. The pipe's role is a
    parameter, so an update can switch it without touching anything else."""
    tags = [{"Key": "sim2real", "Value": CHECK}]

    def _role(may_read_source: bool) -> dict:
        statements = [{"Effect": "Allow", "Action": ["sqs:SendMessage"],
                       "Resource": {"Fn::GetAtt": ["TargetQueue", "Arn"]}}]
        if may_read_source:
            statements.append({
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                "Resource": {"Fn::GetAtt": ["SourceQueue", "Arn"]},
            })
        return {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow",
                                   "Principal": {"Service": "pipes.amazonaws.com"},
                                   "Action": "sts:AssumeRole"}],
                },
                "Policies": [{"PolicyName": "pipe-sqs", "PolicyDocument": {
                    "Version": "2012-10-17", "Statement": statements}}],
                "Tags": tags,
            },
        }

    return {
        "Parameters": {"PipeRole": {"Type": "String", "AllowedValues": ["good", "bad"]}},
        "Conditions": {"UseGood": {"Fn::Equals": [{"Ref": "PipeRole"}, "good"]}},
        "Resources": {
            "SourceQueue": {"Type": "AWS::SQS::Queue", "Properties": {"Tags": tags}},
            "TargetQueue": {"Type": "AWS::SQS::Queue", "Properties": {"Tags": tags}},
            "GoodRole": _role(True),
            "BadRole": _role(False),
            "ThePipe": {
                "Type": "AWS::Pipes::Pipe",
                "Properties": {
                    "Name": pipe_name,
                    "RoleArn": {"Fn::If": ["UseGood", {"Fn::GetAtt": ["GoodRole", "Arn"]},
                                           {"Fn::GetAtt": ["BadRole", "Arn"]}]},
                    "Source": {"Fn::GetAtt": ["SourceQueue", "Arn"]},
                    "SourceParameters": {"SqsQueueParameters": {"BatchSize": 1}},
                    "Target": {"Fn::GetAtt": ["TargetQueue", "Arn"]},
                    "DesiredState": "RUNNING",
                    "Tags": {"sim2real": CHECK},
                },
            },
        },
        "Outputs": {
            "SourceQueueUrl": {"Value": {"Ref": "SourceQueue"}},
            "TargetQueueUrl": {"Value": {"Ref": "TargetQueue"}},
            "GoodRoleArn": {"Value": {"Fn::GetAtt": ["GoodRole", "Arn"]}},
        },
    }


def _create_stack(ctx, cfn, name: str, template: dict) -> str:
    stack_id = cfn.create_stack(
        StackName=name, TemplateBody=json.dumps(template), Capabilities=["CAPABILITY_IAM"],
        Parameters=[{"ParameterKey": "PipeRole", "ParameterValue": "good"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    return stack_id


def _wait_stack(cfn, stack_id: str, *, timeout_s: float = _STACK_TIMEOUT_S) -> str:
    """Poll to the first non-IN_PROGRESS status and return it."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if not status.endswith("_IN_PROGRESS"):
            return status
        time.sleep(2)
    raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s}s")


def _delete_stack(cfn, stack_id: str) -> None:
    cfn.delete_stack(StackName=stack_id)
    status = _wait_stack(cfn, stack_id)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} ended {status!r} after DeleteStack")


def _outputs(cfn, stack_id: str) -> dict[str, str]:
    stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _await_record(ctx, queue_url: str, body: str, *, timeout_s: float) -> dict:
    """Receive (and delete) until a pipe-delivered record with this source body arrives."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            record = json.loads(msg["Body"])
            if record.get("body") == body:
                return record
    raise AssertionError(f"no record with body {body!r} reached the target within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
