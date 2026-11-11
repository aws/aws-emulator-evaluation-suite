"""deploy-cfn-pipe-whose-role-cannot-read-its-source-fails-the-stack-and-rolls-back."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-pipe-whose-role-cannot-read-its-source-fails-the-stack-and-rolls-back"
GROUP = "deploy"
SERVICES = ["pipes"]

# The failing stack takes about three minutes to reach ROLLBACK_COMPLETE.
_STACK_TIMEOUT_S = 600.0
_DELIVERY_TIMEOUT_S = 120.0


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A stack whose pipe role cannot ReceiveMessage on the source fails and rolls back.

    The pipe is CREATE_FAILED with the Pipes StateReason, the stack ends ROLLBACK_COMPLETE with no pipe
    left; the same stack with read permission, created alongside, deploys and delivers a record.
    """
    cfn = ctx.client("cloudformation")
    pipes = ctx.client("pipes")
    sqs = ctx.client("sqs")

    bad_pipe = ctx.unique_name("sim2real-pipes-cfn-pipe-")
    good_pipe = ctx.unique_name("sim2real-pipes-cfn-pipe-")
    bad = _create_stack(ctx, cfn, ctx.unique_name("sim2real-pipes-cfn-"),
                        _template(bad_pipe, may_read_source=False, filter_value=None))
    good = _create_stack(ctx, cfn, ctx.unique_name("sim2real-pipes-cfn-"),
                         _template(good_pipe, may_read_source=True, filter_value=None))

    status = _wait_stack(cfn, bad)
    assert status == "ROLLBACK_COMPLETE", (
        f"the stack whose pipe role cannot read the source ended {status!r}, expected "
        f"ROLLBACK_COMPLETE"
    )
    failures = [
        e for page in cfn.get_paginator("describe_stack_events").paginate(StackName=bad)
        for e in page["StackEvents"]
        if e["LogicalResourceId"] == "ThePipe" and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert len(failures) == 1, f"expected one CREATE_FAILED event for ThePipe, got {failures!r}"
    reason = failures[0].get("ResourceStatusReason", "")
    head, sep, tail = reason.partition(" (RequestToken: ")
    expected_head = (
        "Resource handler returned message: \"Resource of type 'AWS::Pipes::Pipe' with "
        f"identifier '{bad_pipe}' did not stabilize. Status Reason is Input parameter is invalid "
        "from the request due to : The provided customer role does not have permissions to call "
        "ReceiveMessage on SQS\""
    )
    assert head == expected_head and sep, (
        f"ThePipe failed with reason {reason!r}; expected it to start {expected_head!r} followed "
        f"by a request token"
    )
    assert tail.endswith(", HandlerErrorCode: NotStabilized)"), (
        f"ThePipe's failure must be classified NotStabilized, reason was {reason!r}"
    )
    code, message = _error(lambda: pipes.describe_pipe(Name=bad_pipe))
    assert (code, message) == ("NotFoundException", f"Pipe {bad_pipe} does not exist."), (
        f"after rollback the failed pipe must be gone; DescribePipe gave {code!r}: {message!r}"
    )

    status = _wait_stack(cfn, good)
    assert status == "CREATE_COMPLETE", f"the control stack ended {status!r}"
    assert pipes.describe_pipe(Name=good_pipe)["CurrentState"] == "RUNNING", (
        "the control stack's pipe is not RUNNING"
    )
    out = _outputs(cfn, good)
    body = json.dumps({"k": "control", "m": ctx.unique_name("m-")})
    sqs.send_message(QueueUrl=out["SourceQueueUrl"], MessageBody=body)
    _await_record(ctx, out["TargetQueueUrl"], body, timeout_s=_DELIVERY_TIMEOUT_S)



def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")



def _template(pipe_name: str, *, may_read_source: bool, filter_value: str | None) -> dict:
    statements = [{"Effect": "Allow", "Action": ["sqs:SendMessage"],
                   "Resource": {"Fn::GetAtt": ["TargetQueue", "Arn"]}}]
    if may_read_source:
        statements.append({
            "Effect": "Allow",
            "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
            "Resource": {"Fn::GetAtt": ["SourceQueue", "Arn"]},
        })
    source_parameters: dict = {"SqsQueueParameters": {"BatchSize": 1}}
    if filter_value is not None:
        source_parameters["FilterCriteria"] = {
            "Filters": [{"Pattern": json.dumps({"body": {"k": [filter_value]}})}]
        }
    tags = [{"Key": "sim2real", "Value": CHECK}]
    return {
        "Resources": {
            "SourceQueue": {"Type": "AWS::SQS::Queue", "Properties": {"Tags": tags}},
            "TargetQueue": {"Type": "AWS::SQS::Queue", "Properties": {"Tags": tags}},
            "PipeRole": {
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
            },
            "ThePipe": {
                "Type": "AWS::Pipes::Pipe",
                "Properties": {
                    "Name": pipe_name,
                    "RoleArn": {"Fn::GetAtt": ["PipeRole", "Arn"]},
                    "Source": {"Fn::GetAtt": ["SourceQueue", "Arn"]},
                    "SourceParameters": source_parameters,
                    "Target": {"Fn::GetAtt": ["TargetQueue", "Arn"]},
                    "DesiredState": "RUNNING",
                    "Tags": {"sim2real": CHECK},
                },
            },
        },
        "Outputs": {
            "SourceQueueUrl": {"Value": {"Ref": "SourceQueue"}},
            "TargetQueueUrl": {"Value": {"Ref": "TargetQueue"}},
        },
    }


def _create_stack(ctx, cfn, name: str, template: dict) -> str:
    stack_id = cfn.create_stack(
        StackName=name, TemplateBody=json.dumps(template), Capabilities=["CAPABILITY_IAM"],
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
