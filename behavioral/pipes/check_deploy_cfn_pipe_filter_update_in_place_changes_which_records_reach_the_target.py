"""deploy-cfn-pipe-filter-update-in-place-changes-which-records-reach-the-target."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-cfn-pipe-filter-update-in-place-changes-which-records-reach-the-target"
GROUP = "deploy"
SERVICES = ["pipes"]

_STACK_TIMEOUT_S = 600.0
_DELIVERY_TIMEOUT_S = 120.0
_CONVERGE_TIMEOUT_S = 300.0


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:eventing",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A FilterCriteria-only stack update keeps the pipe (same ARN and CreationTime, later
    LastModifiedTime, RUNNING), and it then forwards only records the new filter matches.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-event-filtering.html
    """
    cfn = ctx.client("cloudformation")
    pipes = ctx.client("pipes")
    sqs = ctx.client("sqs")

    pipe_name = ctx.unique_name("sim2real-pipes-cfn-pipe-")
    stack = _create_stack(ctx, cfn, ctx.unique_name("sim2real-pipes-cfn-"),
                          _template(pipe_name, may_read_source=True, filter_value="a"))
    status = _wait_stack(cfn, stack)
    assert status == "CREATE_COMPLETE", f"the stack ended {status!r}"
    out = _outputs(cfn, stack)
    src, tgt = out["SourceQueueUrl"], out["TargetQueueUrl"]
    before = pipes.describe_pipe(Name=pipe_name)
    assert before["CurrentState"] == "RUNNING", f"the deployed pipe is {before['CurrentState']!r}"

    first = json.dumps({"k": "a", "m": ctx.unique_name("m-")})
    sqs.send_message(QueueUrl=src, MessageBody=first)
    _await_record(ctx, tgt, first, timeout_s=_DELIVERY_TIMEOUT_S)

    cfn.update_stack(StackName=stack, Capabilities=["CAPABILITY_IAM"], TemplateBody=json.dumps(
        _template(pipe_name, may_read_source=True, filter_value="b")))
    status = _wait_stack(cfn, stack)
    assert status == "UPDATE_COMPLETE", f"the filter update ended {status!r}"

    after = pipes.describe_pipe(Name=pipe_name)
    assert (after["Arn"], after["CreationTime"]) == (before["Arn"], before["CreationTime"]), (
        f"a FilterCriteria-only update must not replace the pipe: ARN/CreationTime went from "
        f"{before['Arn']!r}/{before['CreationTime']!r} to {after['Arn']!r}/{after['CreationTime']!r}"
    )
    assert after["LastModifiedTime"] > before["LastModifiedTime"], (
        f"the update did not advance LastModifiedTime ({before['LastModifiedTime']!r} -> "
        f"{after['LastModifiedTime']!r})"
    )
    assert after["CurrentState"] == "RUNNING", f"after the update the pipe is {after['CurrentState']!r}"
    patterns = [json.loads(f["Pattern"]) for f in after["SourceParameters"]["FilterCriteria"]["Filters"]]
    assert patterns == [{"body": {"k": ["b"]}}], f"the updated pipe filters on {patterns!r}"

    # The update reaches the poller eventually, not at UPDATE_COMPLETE: probe with k=b records
    # until the first one is forwarded, which is the point from which the new filter is live.
    delivered: list[str] = []
    probes: list[str] = []
    deadline = time.monotonic() + _CONVERGE_TIMEOUT_S
    while time.monotonic() < deadline and not set(probes) & set(delivered):
        probe = json.dumps({"k": "b", "m": ctx.unique_name("probe-")})
        probes.append(probe)
        sqs.send_message(QueueUrl=src, MessageBody=probe)
        for _ in range(3):
            delivered += _receive_bodies(ctx, tgt)
    assert set(probes) & set(delivered), (
        f"none of {len(probes)} k=b records was forwarded within {_CONVERGE_TIMEOUT_S}s of "
        f"UPDATE_COMPLETE, so the new filter never took effect; the target received {delivered!r}"
    )

    dropped = json.dumps({"k": "a", "m": ctx.unique_name("m-")})
    kept = json.dumps({"k": "b", "m": ctx.unique_name("m-")})
    sqs.send_message(QueueUrl=src, MessageBody=dropped)
    sqs.send_message(QueueUrl=src, MessageBody=kept)

    deadline = time.monotonic() + _DELIVERY_TIMEOUT_S
    while kept not in delivered and time.monotonic() < deadline:
        delivered += _receive_bodies(ctx, tgt)
    assert kept in delivered, (
        f"the k=b record the new filter matches never reached the target; it received {delivered!r}"
    )
    # A filtered-out record is deleted from the source, not left behind, so the source drains.
    deadline = time.monotonic() + _DELIVERY_TIMEOUT_S
    left = None
    while time.monotonic() < deadline:
        attrs = sqs.get_queue_attributes(QueueUrl=src, AttributeNames=[
            "ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"])["Attributes"]
        left = int(attrs["ApproximateNumberOfMessages"]) + int(attrs["ApproximateNumberOfMessagesNotVisible"])
        if left == 0:
            break
        time.sleep(5)
    assert left == 0, f"the source still holds {left} record(s); the filtered-out one was not consumed"
    delivered += _receive_bodies(ctx, tgt) + _receive_bodies(ctx, tgt)
    assert dropped not in delivered, (
        f"the k=a record matches only the OLD filter, yet the updated pipe delivered it: {delivered!r}"
    )


def _receive_bodies(ctx, queue_url: str) -> list[str]:
    sqs = ctx.client("sqs")
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
    bodies = []
    for msg in resp.get("Messages", []):
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        bodies.append(json.loads(msg["Body"]).get("body"))
    return bodies


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
