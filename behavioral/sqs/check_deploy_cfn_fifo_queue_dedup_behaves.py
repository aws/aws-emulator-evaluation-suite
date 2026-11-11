"""deploy-cfn-fifo-queue-dedup-behaves."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-cfn-fifo-queue-dedup-behaves"
GROUP = "deploy"
SERVICES = ["sqs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A CloudFormation-deployed FIFO queue with ContentBasedDeduplication enabled
    enforces content-based dedup and strict per-group ordering exactly as a
    manually-created FIFO queue would."""
    queue_name = ctx.unique_name("sim2real-behav-cfnfifo-") + ".fifo"
    template = {
        "Parameters": {"QueueName": {"Type": "String"}},
        "Resources": {
            "Queue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {
                    "QueueName": {"Ref": "QueueName"},
                    "FifoQueue": True,
                    "ContentBasedDeduplication": True,
                },
            }
        },
        "Outputs": {"QueueUrl": {"Value": {"Ref": "Queue"}}},
    }
    _, outputs = _deploy_stack(ctx, template, {"QueueName": queue_name})
    queue_url = outputs["QueueUrl"]
    sqs = ctx.client("sqs")

    group = "grp-1"
    # First two sends are identical content -> content-based dedup must collapse
    # them into a single delivered message. The following three are distinct and
    # must be delivered in the exact order sent (FIFO group ordering).
    bodies_sent = ["dup-content", "dup-content", "seq-1", "seq-2", "seq-3"]
    for b in bodies_sent:
        sqs.send_message(QueueUrl=queue_url, MessageBody=b, MessageGroupId=group)

    expected = ["dup-content", "seq-1", "seq-2", "seq-3"]
    received_bodies = []
    deadline = time.monotonic() + 40.0
    while len(received_bodies) < len(expected) and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            received_bodies.append(m["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])

    assert received_bodies == expected, (
        f"expected deduped+ordered {expected}, got {received_bodies}"
    )


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

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Parameters=params,
        Tags=[{"Key": "sim2real", "Value": "true"}],
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
