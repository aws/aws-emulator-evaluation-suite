"""cfn-sqs-queue-create-visibility-timeout-over-limit-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-sqs-queue-create-visibility-timeout-over-limit-rejected"
GROUP = "resource-existence"
SERVICES = ["cloudformation", "sqs"]

_STACK_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}

# CloudFormation's resource-handler wrapping of the service error; the request id and token vary.
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*) \(Service: (?P<service>[A-Za-z0-9]+), '
    r'Status Code: (?P<status>\d+), Request ID: [^)]*\)(?: \(SDK Attempt Count: \d+\))?" '
    r'\(RequestToken: [^,]*, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$'
)


def _delete_stack_and_wait(cfn, stack_id: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cfn.delete_stack(StackName=stack_id)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _wait_stack(cfn, stack_id: str, *, timeout_s: float = 240.0, interval_s: float = 2.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last in _STACK_TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_id!r} not terminal within {timeout_s}s (last={last!r})")


def _resource_failure(cfn, stack_id: str, logical_id: str) -> tuple[str, str, str, str]:
    """``(message, service, status, HandlerErrorCode)`` from the CREATE_FAILED event for *logical_id*."""
    for event in cfn.describe_stack_events(StackName=stack_id)["StackEvents"]:
        if event["LogicalResourceId"] != logical_id or event["ResourceStatus"] != "CREATE_FAILED":
            continue
        reason = event.get("ResourceStatusReason", "")
        match = _HANDLER_REASON.match(reason)
        if match:
            return match["message"], match["service"], match["status"], match["code"]
        raise AssertionError(f"could not parse handler reason: {reason!r}")
    raise AssertionError(f"no CREATE_FAILED event for {logical_id!r} in stack {stack_id!r}")


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::SQS::Queue whose VisibilityTimeout exceeds SQS's maximum rolls back
    with SQS's error and no queue ever created, while the same template with a valid value deploys."""
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")

    bad_queue_name = ctx.unique_name("sim2real-behav-cfn-sqsbad-")
    bad_stack_name = ctx.unique_name("sim2real-behav-cfn-sqsbad-")
    bad_stack_id = cfn.create_stack(
        StackName=bad_stack_name,
        TemplateBody=json.dumps({
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Queue": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {"QueueName": bad_queue_name, "VisibilityTimeout": 43201},
                },
            },
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, bad_stack_id))

    status = _wait_stack(cfn, bad_stack_id)
    assert status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {status!r}"

    got_error = _resource_failure(cfn, bad_stack_id, "Queue")
    want_error = ("Invalid value for the parameter VisibilityTimeout.", "Sqs", "400", "InvalidRequest")
    assert got_error == want_error, f"CREATE_FAILED reason: expected {want_error!r}, got {got_error!r}"

    try:
        sqs.get_queue_url(QueueName=bad_queue_name)
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "AWS.SimpleQueueService.NonExistentQueue", (
            f"expected the never-created queue to be NonExistentQueue, got "
            f"{exc.response['Error']['Code']!r}"
        )
        assert exc.response["Error"]["Message"] == "The specified queue does not exist.", (
            f"expected the standard NonExistentQueue message, got "
            f"{exc.response['Error']['Message']!r}"
        )
    else:
        raise AssertionError(f"queue {bad_queue_name!r} unexpectedly exists")

    # Positive control, in the same file: a validly-configured queue deploys cleanly.
    good_queue_name = ctx.unique_name("sim2real-behav-cfn-sqsok-")
    good_stack_name = ctx.unique_name("sim2real-behav-cfn-sqsok-")
    good_stack_id = cfn.create_stack(
        StackName=good_stack_name,
        TemplateBody=json.dumps({
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Queue": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {"QueueName": good_queue_name, "VisibilityTimeout": 90},
                },
            },
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, good_stack_id))
    good_status = _wait_stack(cfn, good_stack_id)
    assert good_status == "CREATE_COMPLETE", f"control stack: expected CREATE_COMPLETE, got {good_status!r}"
    sqs.get_queue_url(QueueName=good_queue_name)  # control: the valid queue is real

    for stack_id in (bad_stack_id, good_stack_id):
        _delete_stack_and_wait(cfn, stack_id)
        final = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        assert final == "DELETE_COMPLETE", f"stack {stack_id} delete ended {final!r}"
    got = _error(lambda: sqs.get_queue_url(QueueName=good_queue_name))
    assert got == ("AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist."), (
        f"the control queue after its stack delete: {got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
