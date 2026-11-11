"""cfn-sqs-queue-readonly-arn-ignored-and-ref-getatt-match-sqs."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-sqs-queue-readonly-arn-ignored-and-ref-getatt-match-sqs"
GROUP = "deploy"
SERVICES = ["cloudformation", "sqs"]

_FAKE_ACCOUNT = "111122223333"

_STACK_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
                   "DELETE_COMPLETE", "DELETE_FAILED"}


def _wait_stack(cfn, stack_id: str, *, timeout_s: float = 240.0, interval_s: float = 2.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last in _STACK_TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_id!r} not terminal within {timeout_s}s (last={last!r})")


def _delete_stack_and_wait(cfn, stack_id: str) -> None:
    cfn.delete_stack(StackName=stack_id)
    status = _wait_stack(cfn, stack_id)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id!r} delete ended {status!r}")


def _outputs(cfn, stack_id: str) -> dict:
    return {o["OutputKey"]: o["OutputValue"]
            for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]}


def _physical_id(cfn, stack_id: str, logical: str) -> str:
    resources = cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    for r in resources:
        if r["LogicalResourceId"] == logical:
            return r["PhysicalResourceId"]
    raise AssertionError(f"no resource {logical!r} in stack {stack_id!r}: {resources!r}")


def _wait_gone(call, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    """Poll ``call`` until it raises SQS's not-found error; the physical delete may lag
    DELETE_COMPLETE. Returns ``(code, message)``."""
    deadline = time.monotonic() + timeout_s
    last_code, last_message = None, None
    while time.monotonic() < deadline:
        try:
            call()
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            last_message = exc.response["Error"]["Message"]
            if last_code == "AWS.SimpleQueueService.NonExistentQueue":
                return last_code, last_message
        else:
            last_code, last_message = None, None
        time.sleep(interval_s)
    raise AssertionError(
        f"queue still answering after {timeout_s}s of polling "
        f"(last_code={last_code!r}, last_message={last_message!r})")


def _template(queue_name: str, bogus_arn: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Queue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {
                    "QueueName": queue_name,
                    "VisibilityTimeout": 77,
                    "Tags": [{"Key": "sim2real", "Value": CHECK}],
                    # Arn is readOnlyProperties but not the primaryIdentifier; AWS ignores a
                    # value supplied for it rather than refusing the create.
                    "Arn": bogus_arn,
                },
            },
        },
        "Outputs": {
            "QueueRef": {"Value": {"Ref": "Queue"}},
            "QueueUrlAttr": {"Value": {"Fn::GetAtt": ["Queue", "QueueUrl"]}},
            "QueueArnAttr": {"Value": {"Fn::GetAtt": ["Queue", "Arn"]}},
        },
    })


@tags(
    "axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control",
)
def run(ctx) -> None:
    """A template that sets AWS::SQS::Queue's readOnlyProperty Arn deploys as if it were
    absent: Ref and every declared Fn::GetAtt equal SQS's own answer for the queue it created,
    whose ARN is the documented one and whose VisibilityTimeout and Tags read back."""
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")

    queue_name = ctx.unique_name("sim2real-behav-cfnro-sqs-")
    stack_name = ctx.unique_name("sim2real-behav-cfnro-sqs-stk-")
    bogus_arn = f"arn:aws:sqs:{ctx.region}:{_FAKE_ACCOUNT}:not-the-real-queue"

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(queue_name, bogus_arn),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_id))

    status = _wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"a readOnlyProperty value in the template must not block the create; got {status!r}")

    real_url = sqs.get_queue_url(QueueName=queue_name)["QueueUrl"]
    physical = _physical_id(cfn, stack_id, "Queue")
    assert physical == real_url, (
        f"the stack's physical id {physical!r} is not SQS's own url {real_url!r}")

    attrs = sqs.get_queue_attributes(
        QueueUrl=real_url, AttributeNames=["QueueArn", "VisibilityTimeout"]
    )["Attributes"]
    real_arn = attrs["QueueArn"]
    assert real_arn == f"arn:aws:sqs:{ctx.region}:{ctx.account}:{queue_name}", (
        f"SQS's QueueArn is not the documented ARN of {queue_name!r}: {real_arn!r}")
    assert attrs["VisibilityTimeout"] == "77", (
        f"VisibilityTimeout 77 did not reach SQS: {attrs['VisibilityTimeout']!r}")
    queue_tags = sqs.list_queue_tags(QueueUrl=real_url).get("Tags", {})
    own_tags = {k: v for k, v in queue_tags.items() if not k.startswith("aws:")}
    assert own_tags == {"sim2real": CHECK}, f"the queue's Tags read back as {own_tags!r}"

    outputs = _outputs(cfn, stack_id)
    assert outputs["QueueRef"] == real_url, (
        f"Ref must equal the real queue url {real_url!r}; got {outputs['QueueRef']!r}")
    assert outputs["QueueUrlAttr"] == real_url, (
        f"GetAtt QueueUrl must equal the real queue url {real_url!r}; got "
        f"{outputs['QueueUrlAttr']!r}")
    assert outputs["QueueArnAttr"] == real_arn, (
        f"GetAtt Arn must equal SQS's own QueueArn {real_arn!r}; got {outputs['QueueArnAttr']!r}")

    _delete_stack_and_wait(cfn, stack_id)
    code, message = _wait_gone(
        lambda: sqs.get_queue_attributes(QueueUrl=real_url, AttributeNames=["QueueArn"]))
    assert code == "AWS.SimpleQueueService.NonExistentQueue", (
        f"expected the NonExistentQueue code after stack delete, got {code!r}")
    assert message == "The specified queue does not exist.", (
        f"expected the standard NonExistentQueue message, got {message!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
