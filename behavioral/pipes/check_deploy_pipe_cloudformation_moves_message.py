"""deploy-pipe-cloudformation-moves-message."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "deploy-pipe-cloudformation-moves-message"
GROUP = "deploy"
SERVICES = ["pipes"]

_TEMPLATE = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Parameters": {
        "PipeName": {"Type": "String"},
        "SourceQueueName": {"Type": "String"},
        "TargetQueueName": {"Type": "String"},
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
                        "PolicyName": "PipeAccess",
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
                "Target": {"Fn::GetAtt": ["TargetQueue", "Arn"]},
                "DesiredState": "RUNNING",
            },
        },
    },
    "Outputs": {
        "SourceQueueUrl": {"Value": {"Ref": "SourceQueue"}},
        "TargetQueueUrl": {"Value": {"Ref": "TargetQueue"}},
    },
}


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A pipe created via CloudFormation actually moves a message end to end."""
    cfn = ctx.client("cloudformation")
    pipes = ctx.client("pipes")
    sqs = ctx.client("sqs")

    stack_name = ctx.unique_name("sim2real-pipes-cfn-")
    pipe_name = ctx.unique_name("sim2real-pipes-cfn-pipe-")
    source_name = ctx.unique_name("sim2real-pipes-cfn-src-")
    target_name = ctx.unique_name("sim2real-pipes-cfn-dst-")

    def _cleanup_stack() -> None:
        cfn.delete_stack(StackName=stack_name)
        waiter = cfn.get_waiter("stack_delete_complete")
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(_TEMPLATE),
        Parameters=[
            {"ParameterKey": "PipeName", "ParameterValue": pipe_name},
            {"ParameterKey": "SourceQueueName", "ParameterValue": source_name},
            {"ParameterKey": "TargetQueueName", "ParameterValue": target_name},
        ],
        Capabilities=["CAPABILITY_IAM"],
    )

    ctx.on_cleanup(_cleanup_stack)

    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450})

    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert stack["StackStatus"] == "CREATE_COMPLETE"
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack["Outputs"]}
    source_url = outputs["SourceQueueUrl"]
    target_url = outputs["TargetQueueUrl"]

    described = pipes.describe_pipe(Name=pipe_name)
    assert described["CurrentState"] == "RUNNING"

    marker = uuid.uuid4().hex
    sqs.send_message(QueueUrl=source_url, MessageBody=f"cfn-payload-{marker}")

    deadline = time.monotonic() + 90.0
    delivered = None
    while time.monotonic() < deadline and delivered is None:
        resp = sqs.receive_message(QueueUrl=target_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=target_url, ReceiptHandle=msg["ReceiptHandle"])
            if marker in msg["Body"]:
                delivered = msg["Body"]
                break

    assert delivered is not None, "message sent to CFN-templated source queue never reached target queue"
    assert marker in delivered, f"expected marker {marker!r} in delivered body, got {delivered!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
