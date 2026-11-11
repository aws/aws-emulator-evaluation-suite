"""deploy-pipe-via-cloudformation-behaves."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "deploy-pipe-via-cloudformation-behaves"
GROUP = "deploy"
SERVICES = ["pipes"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN stack declaring AWS::Pipes::Pipe + source/target SQS queues reaches
    CREATE_COMPLETE and the deployed pipe actually forwards a message end-to-end."""
    cfn = ctx.client("cloudformation")

    stack_name = ctx.unique_name("sim2real-pipe-cfn-")
    source_name = ctx.unique_name("sim2real-pipe-cfn-src-")
    target_name = ctx.unique_name("sim2real-pipe-cfn-tgt-")
    pipe_name = ctx.unique_name("sim2real-pipe-cfn-pipe-")

    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {
                "SourceQueueName": {"Type": "String"},
                "TargetQueueName": {"Type": "String"},
                "PipeName": {"Type": "String"},
            },
            "Resources": {
                "SourceQueue": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {"QueueName": {"Ref": "SourceQueueName"}},
                },
                "TargetQueue": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {"QueueName": {"Ref": "TargetQueueName"}},
                },
                "PipeRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "pipes.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "Policies": [
                            {
                                "PolicyName": "pipe-access",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": [
                                                "sqs:ReceiveMessage",
                                                "sqs:DeleteMessage",
                                                "sqs:GetQueueAttributes",
                                            ],
                                            "Resource": {"Fn::GetAtt": ["SourceQueue", "Arn"]},
                                        },
                                        {
                                            "Effect": "Allow",
                                            "Action": ["sqs:SendMessage"],
                                            "Resource": {"Fn::GetAtt": ["TargetQueue", "Arn"]},
                                        },
                                    ],
                                },
                            }
                        ],
                    },
                },
                "Pipe": {
                    "Type": "AWS::Pipes::Pipe",
                    "Properties": {
                        "Name": {"Ref": "PipeName"},
                        "RoleArn": {"Fn::GetAtt": ["PipeRole", "Arn"]},
                        "Source": {"Fn::GetAtt": ["SourceQueue", "Arn"]},
                        "SourceParameters": {"SqsQueueParameters": {"BatchSize": 1}},
                        "Target": {"Fn::GetAtt": ["TargetQueue", "Arn"]},
                        "TargetParameters": {"InputTemplate": "<$.body>"},
                        "DesiredState": "RUNNING",
                    },
                },
            },
        }
    )

    def _cleanup_stack():
        cfn.delete_stack(StackName=stack_name)
        waiter = cfn.get_waiter("stack_delete_complete")
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450})

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Parameters=[
            {"ParameterKey": "SourceQueueName", "ParameterValue": source_name},
            {"ParameterKey": "TargetQueueName", "ParameterValue": target_name},
            {"ParameterKey": "PipeName", "ParameterValue": pipe_name},
        ],
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )

    ctx.on_cleanup(_cleanup_stack)

    create_waiter = cfn.get_waiter("stack_create_complete")
    create_waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450})

    _wait_pipe_state(ctx, pipe_name, {"RUNNING"}, timeout_s=120.0)

    sqs = ctx.client("sqs")
    source_url = sqs.get_queue_url(QueueName=source_name)["QueueUrl"]
    target_url = sqs.get_queue_url(QueueName=target_name)["QueueUrl"]

    body = f"cfn-pipe-payload-{uuid.uuid4()}"
    sqs.send_message(QueueUrl=source_url, MessageBody=body)

    received = _poll_for_message_body(ctx, target_url, timeout_s=220.0)
    assert received == body, f"expected {body!r} on target queue via CFN-deployed pipe, got {received!r}"


_TERMINAL_FAILURE_STATES = {
    "CREATE_FAILED",
    "START_FAILED",
    "UPDATE_FAILED",
    "DELETE_FAILED",
    "CREATE_ROLLBACK_FAILED",
    "DELETE_ROLLBACK_FAILED",
    "UPDATE_ROLLBACK_FAILED",
}


def _wait_pipe_state(ctx, name, states, timeout_s=120.0, interval_s=5.0):
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = pipes.describe_pipe(Name=name)
        last = desc["CurrentState"]
        if last in states:
            return desc
        if last in _TERMINAL_FAILURE_STATES:
            raise AssertionError(f"pipe {name} entered failure state {last}: {desc.get('StateReason')}")
        time.sleep(interval_s)
    raise AssertionError(f"pipe {name} did not reach {states} within {timeout_s}s (last={last})")


def _poll_for_message_body(ctx, queue_url, timeout_s=60.0):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        msgs = resp.get("Messages", [])
        if msgs:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msgs[0]["ReceiptHandle"])
            return msgs[0]["Body"]
        time.sleep(1.0)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
