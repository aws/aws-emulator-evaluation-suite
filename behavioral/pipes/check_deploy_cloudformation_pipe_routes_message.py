"""deploy-cloudformation-pipe-routes-message."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "deploy-cloudformation-pipe-routes-message"
GROUP = "deploy"
SERVICES = ["pipes"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A pipe deployed via a CloudFormation template (AWS::Pipes::Pipe, together with its
    SQS queues and IAM role) reaches CREATE_COMPLETE and then actually routes a message
    from its declared source queue to its declared target queue."""
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")

    stack_name = ctx.unique_name("sim2real-pipes-cfn-")
    pipe_name = ctx.unique_name("sim2real-pipes-cfn-pipe-")

    template = {
        "Resources": {
            "SourceQueue": {"Type": "AWS::SQS::Queue"},
            "TargetQueue": {"Type": "AWS::SQS::Queue"},
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
                },
            },
            "ThePipe": {
                "Type": "AWS::Pipes::Pipe",
                "Properties": {
                    "Name": pipe_name,
                    "RoleArn": {"Fn::GetAtt": ["PipeRole", "Arn"]},
                    "Source": {"Fn::GetAtt": ["SourceQueue", "Arn"]},
                    "SourceParameters": {"SqsQueueParameters": {"BatchSize": 1}},
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

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(ctx, cfn, stack_id))

    _wait_stack_status(ctx, cfn, stack_name, {"CREATE_COMPLETE"}, timeout_s=300)

    outputs = {o["OutputKey"]: o["OutputValue"] for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]}
    src_url = outputs["SourceQueueUrl"]
    tgt_url = outputs["TargetQueueUrl"]

    content = f"cfn-payload-{uuid.uuid4().hex[:12]}"
    sqs.send_message(QueueUrl=src_url, MessageBody=content)

    delivered = _wait_for_target_message(ctx, tgt_url, content, timeout_s=120)
    assert delivered == content, f"expected {content!r} on target queue via CFN-deployed pipe, got {delivered!r}"


def _wait_stack_status(ctx, cfn, stack_name, statuses, timeout_s=300, interval_s=10):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last in statuses:
            return last
        if last.endswith("FAILED") or last.endswith("ROLLBACK_COMPLETE"):
            raise AssertionError(f"stack {stack_name} entered {last} while waiting for {statuses}")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} never reached {statuses}, last status was {last}")


def _delete_stack(ctx, cfn, stack_id):
    # Addressed by stack id, so DescribeStacks keeps reporting the deleted stack as
    # DELETE_COMPLETE; a DELETE_FAILED or a timeout raises instead of leaking silently.
    cfn.delete_stack(StackName=stack_id)
    _wait_stack_status(ctx, cfn, stack_id, {"DELETE_COMPLETE"}, timeout_s=300)


def _wait_for_target_message(ctx, tgt_url, expected_body, timeout_s=120):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=tgt_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            payload = json.loads(msg["Body"])
            record = payload[0] if isinstance(payload, list) else payload
            sqs.delete_message(QueueUrl=tgt_url, ReceiptHandle=msg["ReceiptHandle"])
            if record.get("body") == expected_body:
                return record["body"]
    raise AssertionError(f"target never received a message with body {expected_body!r} within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
