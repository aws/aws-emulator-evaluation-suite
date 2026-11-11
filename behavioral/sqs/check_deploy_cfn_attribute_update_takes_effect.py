"""deploy-cfn-attribute-update-takes-effect."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-cfn-attribute-update-takes-effect"
GROUP = "deploy"
SERVICES = ["sqs"]


# timing:real-time — visibility: 20 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data", "timing:real-time")
def run(ctx: Any) -> None:
    """Updating a CloudFormation stack's VisibilityTimeout property changes the
    actually-enforced visibility window on the running queue, not merely the
    stored attribute value."""
    queue_name = ctx.unique_name("sim2real-behav-cfnvt-")
    template = _template()
    stack_name, outputs = _deploy_stack(ctx, template, queue_name, "2")
    queue_url = outputs["QueueUrl"]
    sqs = ctx.client("sqs")

    attrs = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["VisibilityTimeout"])
    assert attrs["Attributes"]["VisibilityTimeout"] == "2"

    cfn = ctx.client("cloudformation")
    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Parameters=[
            {"ParameterKey": "QueueName", "ParameterValue": queue_name},
            {"ParameterKey": "VisibilityTimeout", "ParameterValue": "20"},
        ],
    )
    cfn.get_waiter("stack_update_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    attrs = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["VisibilityTimeout"])
    assert attrs["Attributes"]["VisibilityTimeout"] == "20"

    body = f"vt-update-{queue_name}"
    sqs.send_message(QueueUrl=queue_url, MessageBody=body)
    first = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
    assert first.get("Messages"), "expected message to be received"
    assert first["Messages"][0]["Body"] == body

    # The old VisibilityTimeout (2s) would have let the message reappear well
    # within this window; if the update took effect (20s) it must stay hidden.
    deadline = time.monotonic() + 8.0
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=2)
        assert not resp.get("Messages"), (
            "message became visible again before the updated 20s VisibilityTimeout "
            "elapsed -- the CloudFormation update did not take effect on the live queue"
        )

    # sanity: it does eventually reappear (the timeout is not stuck open forever)
    reappeared = None
    deadline = time.monotonic() + 25.0
    while time.monotonic() < deadline and reappeared is None:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        msgs = resp.get("Messages", [])
        if msgs:
            reappeared = msgs[0]
    assert reappeared is not None, "message never reappeared after the updated visibility window"
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=reappeared["ReceiptHandle"])


_MANAGED_TAG_KEY = "sim2real:managed"


def _tags_kv(prefix: str) -> list[dict[str, str]]:
    return [{"Key": _MANAGED_TAG_KEY, "Value": "true"}, {"Key": "sim2real:prefix", "Value": prefix}]


def _template() -> dict:
    return {
        "Parameters": {
            "QueueName": {"Type": "String"},
            "VisibilityTimeout": {"Type": "Number"},
        },
        "Resources": {
            "Queue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {
                    "QueueName": {"Ref": "QueueName"},
                    "VisibilityTimeout": {"Ref": "VisibilityTimeout"},
                    "Tags": _tags_kv("sim2real-behav-cfnvt"),
                },
            }
        },
        "Outputs": {"QueueUrl": {"Value": {"Ref": "Queue"}}},
    }


def _deploy_stack(
    ctx: Any, template: dict, queue_name: str, visibility_timeout: str
) -> tuple[str, dict[str, str]]:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-stack-")
    params = [
        {"ParameterKey": "QueueName", "ParameterValue": queue_name},
        {"ParameterKey": "VisibilityTimeout", "ParameterValue": visibility_timeout},
    ]

    def _cleanup() -> None:
        try:
            cfn.delete_stack(StackName=stack_name)
            cfn.get_waiter("stack_delete_complete").wait(
                StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "StackNotFoundException":
                raise

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Parameters=params,
        Tags=_tags_kv("sim2real-behav-stack"),
    )
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
