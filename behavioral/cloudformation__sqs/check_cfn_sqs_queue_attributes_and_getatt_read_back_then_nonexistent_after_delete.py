"""cfn-sqs-queue-attributes-and-getatt-read-back-then-nonexistent-after-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-sqs-queue-attributes-and-getatt-read-back-then-nonexistent-after-delete"
GROUP = "resource-existence"
SERVICES = ["cloudformation", "sqs"]

_STACK_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}


def _delete_stack_and_wait(cfn, stack_id: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cfn.delete_stack(StackName=stack_id)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": 25}
    )


def _wait_stack(cfn, stack_id: str, *, timeout_s: float = 240.0, interval_s: float = 2.0) -> str:
    """Poll DescribeStacks by stack id (resolves through DELETE_COMPLETE, unlike
    the bare name) until a terminal status; return it."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last in _STACK_TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_id!r} not terminal within {timeout_s}s (last={last!r})")


def _physical_id(cfn, stack_id: str, logical_id: str) -> str:
    resources = cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    for r in resources:
        if r["LogicalResourceId"] == logical_id:
            return r["PhysicalResourceId"]
    raise AssertionError(f"no resource {logical_id!r} in stack {stack_id!r}: {resources!r}")


def _error(fn):
    """``(code, message)`` from the ClientError ``fn`` raises; raises on an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::SQS::Queue is real at SQS: the attributes it
    declared and every Fn::GetAtt attribute it outputs match SQS's own answer, and
    deleting the stack removes the queue from SQS, not just from CFN."""
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    stack_name = ctx.unique_name("sim2real-behav-cfn-sqsq-")

    template = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Queue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {
                    "VisibilityTimeout": 90,
                    "MessageRetentionPeriod": 345600,
                },
            },
        },
        "Outputs": {
            "QueueArn": {"Value": {"Fn::GetAtt": ["Queue", "Arn"]}},
            "QueueName": {"Value": {"Fn::GetAtt": ["Queue", "QueueName"]}},
        },
    })

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_id))

    created = _wait_stack(cfn, stack_id)
    assert created == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {created!r}"

    queue_url = _physical_id(cfn, stack_id, "Queue")

    outputs = {o["OutputKey"]: o["OutputValue"]
               for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]}

    # Independent read at the destination: SQS's own attributes must carry the
    # properties the template declared, and QueueArn must match the GetAtt output.
    attrs = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn", "VisibilityTimeout", "MessageRetentionPeriod"]
    )["Attributes"]
    assert attrs["VisibilityTimeout"] == "90", (
        f"expected VisibilityTimeout '90', got {attrs['VisibilityTimeout']!r}"
    )
    assert attrs["MessageRetentionPeriod"] == "345600", (
        f"expected MessageRetentionPeriod '345600', got {attrs['MessageRetentionPeriod']!r}"
    )
    assert outputs["QueueArn"] == attrs["QueueArn"], (
        f"GetAtt Queue.Arn was {outputs['QueueArn']!r}, SQS's own QueueArn is {attrs['QueueArn']!r}"
    )
    expected_name = queue_url.rsplit("/", 1)[-1]
    assert outputs["QueueName"] == expected_name, (
        f"GetAtt Queue.QueueName was {outputs['QueueName']!r}, expected {expected_name!r} "
        f"(from the queue url {queue_url!r})"
    )

    cfn.delete_stack(StackName=stack_id)
    deleted = _wait_stack(cfn, stack_id)
    assert deleted == "DELETE_COMPLETE", f"expected DELETE_COMPLETE, got {deleted!r}"

    code, message = _wait_gone(
        lambda: sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])
    )
    assert code == "AWS.SimpleQueueService.NonExistentQueue", (
        f"expected the NonExistentQueue code after stack delete, got {code!r}"
    )
    assert message == "The specified queue does not exist.", (
        f"expected the standard NonExistentQueue message, got {message!r}"
    )


def _wait_gone(call, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    """Poll ``call`` until it raises SQS's not-found error; the physical delete may
    lag DELETE_COMPLETE. Returns ``(code, message)``."""
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
        f"(last_code={last_code!r}, last_message={last_message!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
