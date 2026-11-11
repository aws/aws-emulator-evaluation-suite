"""deploy-cfn-dlq-redrive-behaves."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-cfn-dlq-redrive-behaves"
GROUP = "deploy"
SERVICES = ["sqs"]


# timing:real-time — visibility: 1 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:deploy", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx: Any) -> None:
    """A CloudFormation stack wiring a queue's RedrivePolicy to a DLQ actually
    redrives messages to the DLQ once MaxReceiveCount is exceeded on the live,
    deployed resource (not just that the attribute round-trips)."""
    queue_name = ctx.unique_name("sim2real-behav-cfndlq-")
    dlq_name = ctx.unique_name("sim2real-behav-cfndlq-dlq-")
    template = {
        "Parameters": {"QueueName": {"Type": "String"}, "DlqName": {"Type": "String"}},
        "Resources": {
            "Dlq": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": {"Ref": "DlqName"}},
            },
            "Queue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {
                    "QueueName": {"Ref": "QueueName"},
                    "VisibilityTimeout": 1,
                    "RedrivePolicy": {
                        "deadLetterTargetArn": {"Fn::GetAtt": ["Dlq", "Arn"]},
                        "maxReceiveCount": 1,
                    },
                },
            },
        },
        "Outputs": {
            "QueueUrl": {"Value": {"Ref": "Queue"}},
            "DlqUrl": {"Value": {"Ref": "Dlq"}},
        },
    }
    _, outputs = _deploy_stack(ctx, template, {"QueueName": queue_name, "DlqName": dlq_name})
    queue_url = outputs["QueueUrl"]
    dlq_url = outputs["DlqUrl"]
    sqs = ctx.client("sqs")

    body = f"redrive-payload-{queue_name}"
    sqs.send_message(QueueUrl=queue_url, MessageBody=body)

    first = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
    assert first.get("Messages"), "expected first receive to return the message"
    assert first["Messages"][0]["Body"] == body, (
        f"expected first receive body {body!r}, got {first['Messages'][0]['Body']!r}"
    )
    # do NOT delete it -> let the 1s VisibilityTimeout lapse and re-poll so the
    # receive count exceeds maxReceiveCount=1, forcing a move to the DLQ

    # the message must survive its FIRST delivery: a target that redrives on receive #1
    # (ignoring maxReceiveCount entirely) must not pass this check.
    immediate_dlq = sqs.receive_message(QueueUrl=dlq_url, MaxNumberOfMessages=1, WaitTimeSeconds=1)
    assert not immediate_dlq.get("Messages"), (
        "message reached the DLQ after only 1 receive; maxReceiveCount=1 requires it to "
        "survive the first delivery before being redriven"
    )

    dlq_message = None
    deadline = time.monotonic() + 40.0
    while time.monotonic() < deadline and dlq_message is None:
        sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=2)
        resp = sqs.receive_message(QueueUrl=dlq_url, MaxNumberOfMessages=1, WaitTimeSeconds=2)
        msgs = resp.get("Messages", [])
        if msgs:
            dlq_message = msgs[0]

    assert dlq_message is not None, "message was never redriven to the DLQ"
    assert dlq_message["Body"] == body, (
        f"expected redriven DLQ body {body!r}, got {dlq_message['Body']!r}"
    )
    sqs.delete_message(QueueUrl=dlq_url, ReceiptHandle=dlq_message["ReceiptHandle"])

    # the source queue must no longer hold the message
    still_there = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=2)
    assert not still_there.get("Messages"), "message still present on source after redrive"


def _deploy_stack(ctx: Any, template: dict, parameters: dict[str, str]) -> tuple[str, dict[str, str]]:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-stack-")
    params = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]

    def _cleanup() -> None:
        try:
            cfn.delete_stack(StackName=stack_name)
            cfn.get_waiter("stack_delete_complete").wait(
                StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "StackNotFoundException":
                raise

    cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(template), Parameters=params)
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    outputs = {}
    for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", []):
        outputs[o["OutputKey"]] = o["OutputValue"]
    return stack_name, outputs


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
