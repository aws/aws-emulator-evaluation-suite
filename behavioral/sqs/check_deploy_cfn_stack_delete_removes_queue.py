"""deploy-cfn-stack-delete-removes-queue."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-stack-delete-removes-queue"
GROUP = "deploy"
SERVICES = ["sqs"]

_NONEXISTENT_QUEUE_MESSAGE = "The specified queue does not exist."


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """Deleting the CloudFormation stack removes the underlying queue such that
    GetQueueUrl subsequently fails -- not just that the stack reaches
    DELETE_COMPLETE while the queue silently lingers."""
    queue_name = ctx.unique_name("sim2real-behav-cfndel-")
    template = {
        "Parameters": {"QueueName": {"Type": "String"}},
        "Resources": {
            "Queue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": {"Ref": "QueueName"}},
            }
        },
        "Outputs": {"QueueUrl": {"Value": {"Ref": "Queue"}}},
    }
    stack_name, outputs = _deploy_stack(ctx, template, {"QueueName": queue_name})
    queue_url = outputs["QueueUrl"]

    sqs = ctx.client("sqs")
    # sanity: the queue is really there before we delete the stack
    pre_delete_url = sqs.get_queue_url(QueueName=queue_name)["QueueUrl"]
    assert pre_delete_url == queue_url, (
        f"expected GetQueueUrl to match the stack output, got {pre_delete_url!r} vs {queue_url!r}"
    )

    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    # queue deletion can lag stack DELETE_COMPLETE by up to ~60s (SQS async delete)
    error = _poll_until_rejected(lambda: sqs.get_queue_url(QueueName=queue_name), timeout_s=90.0)
    assert error.get("Code") == "AWS.SimpleQueueService.NonExistentQueue", (
        f"expected the queue to disappear after stack deletion, got code={error.get('Code')!r}"
    )
    assert error.get("Message") == _NONEXISTENT_QUEUE_MESSAGE, (
        f"expected message {_NONEXISTENT_QUEUE_MESSAGE!r}, got {error.get('Message')!r}"
    )


def _poll_until_rejected(fn, *, timeout_s: float, interval_s: float = 3.0) -> dict:
    """The botocore Error dict of the first rejected call; still succeeding at the deadline raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as e:
            return e.response["Error"]
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"expected the call to be rejected within {timeout_s}s, but it still SUCCEEDED "
                f"and returned {result!r}"
            )
        time.sleep(interval_s)


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
