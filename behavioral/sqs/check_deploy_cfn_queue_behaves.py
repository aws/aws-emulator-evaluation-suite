"""deploy-cfn-queue-behaves."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-cfn-queue-behaves"
GROUP = "deploy"
SERVICES = ["sqs"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A CloudFormation-deployed AWS::SQS::Queue actually accepts SendMessage/
    ReceiveMessage/DeleteMessage traffic after CREATE_COMPLETE, not just the stack
    status reaching that state."""
    queue_name = ctx.unique_name("sim2real-behav-cfnq-")
    template = {
        "Parameters": {"QueueName": {"Type": "String"}},
        "Resources": {
            "Queue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {
                    "QueueName": {"Ref": "QueueName"},
                    "Tags": [{"Key": "sim2real-behav", "Value": queue_name}],
                },
            }
        },
        "Outputs": {
            "QueueUrl": {"Value": {"Ref": "Queue"}},
            "QueueArn": {"Value": {"Fn::GetAtt": ["Queue", "Arn"]}},
        },
    }
    _, outputs = _deploy_stack(ctx, template, {"QueueName": queue_name})
    queue_url = outputs["QueueUrl"]

    sqs = ctx.client("sqs")
    resolved_url = sqs.get_queue_url(QueueName=queue_name)["QueueUrl"]
    assert resolved_url == queue_url, (
        f"GetQueueUrl {resolved_url!r} does not match the CFN stack's QueueUrl output {queue_url!r}"
    )

    body = f"payload-{queue_name}"
    sqs.send_message(QueueUrl=queue_url, MessageBody=body)

    received = _poll_receive(sqs, queue_url, timeout_s=30.0)
    assert received is not None, "message sent to CFN-deployed queue was never received"
    assert received["Body"] == body, (
        f"received body {received['Body']!r} does not match the sent body {body!r}"
    )
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=received["ReceiptHandle"])

    # confirm the delete actually removed it (bounded poll for absence)
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=2)
        assert not resp.get("Messages"), "deleted message reappeared"


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


def _poll_receive(sqs: Any, queue_url: str, timeout_s: float = 30.0) -> dict | None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        msgs = resp.get("Messages", [])
        if msgs:
            return msgs[0]
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
