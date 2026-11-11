"""deploy-cfn-queue-invalid-message-contents-rejected."""
from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-queue-invalid-message-contents-rejected"
GROUP = "deploy"
SERVICES = ["sqs"]

_INVALID_CONTENTS_MESSAGE = (
    "Invalid binary character '#x1' was found in the message body, the set of allowed characters "
    "is #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]."
)


@tags("axis:rejection", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A CloudFormation-deployed queue rejects a body with characters outside XML 1.0 with
    InvalidMessageContents and never enqueues it, while a valid message on the same queue succeeds.
    """
    queue_name = ctx.unique_name("sim2real-behav-cfnbad-")
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
    _, outputs = _deploy_stack(ctx, template, {"QueueName": queue_name})
    queue_url = outputs["QueueUrl"]
    sqs = ctx.client("sqs")

    invalid_body = "bad-\x01-content"  # \x01 is outside the XML 1.0 character set
    error = _client_error(lambda: sqs.send_message(QueueUrl=queue_url, MessageBody=invalid_body))
    assert error.get("Code") == "InvalidMessageContents", (
        f"expected InvalidMessageContents, got {error.get('Code')!r}"
    )
    assert error.get("Message") == _INVALID_CONTENTS_MESSAGE, (
        f"expected message {_INVALID_CONTENTS_MESSAGE!r}, got {error.get('Message')!r}"
    )

    # the rejected send must not have landed in the queue
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=3)
    assert not resp.get("Messages"), "invalid message was rejected but still enqueued"

    # positive control: a valid message on the same queue must still succeed
    good_body = f"good-{queue_name}"
    sqs.send_message(QueueUrl=queue_url, MessageBody=good_body)
    received = None
    for _ in range(6):
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        msgs = resp.get("Messages", [])
        if msgs:
            received = msgs[0]
            break
    assert received is not None, "positive control: valid message on the same queue was never received"
    assert received["Body"] == good_body, f"expected body {good_body!r}, got {received['Body']!r}"
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=received["ReceiptHandle"])



def _client_error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError rejection, but the call SUCCEEDED and returned {result!r}")


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
