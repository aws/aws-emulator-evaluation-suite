"""create-resource-unknown-extra-property-rejected."""
from __future__ import annotations

import json
import time

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-resource-unknown-extra-property-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A property absent from the resource type's schema makes CreateResource fail, either
    synchronously with ValidationException or asynchronously as FAILED with ErrorCode
    InvalidRequest, rather than being silently dropped and the resource created anyway."""
    cc = ctx.client("cloudcontrol")
    sqs = ctx.client("sqs")

    bad_queue_name = ctx.unique_name("sim2real-behav-ccextra-bad-")
    bad_desired_state = json.dumps(
        {"QueueName": bad_queue_name, "ThisPropertyDoesNotExistInTheSchema": "surprise"}
    )

    ctx.on_cleanup(lambda: _delete_queue_if_exists(sqs, bad_queue_name))
    try:
        progress = cc.create_resource(
            TypeName="AWS::SQS::Queue", DesiredState=bad_desired_state
        )["ProgressEvent"]
    except botocore.exceptions.ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "ValidationException", f"unexpected sync error code: {code}"
        message = err.response["Error"].get("Message", "")
        assert message == (
            "Model validation failed (#: extraneous key [ThisPropertyDoesNotExistInTheSchema] is not permitted)"
        ), f"unexpected sync error message: {message!r}"
    else:
        # Not rejected synchronously -- the handler must still fail the request
        # asynchronously rather than silently dropping the unknown property.
        final = _poll_request_status(ctx, progress["RequestToken"])
        assert final["OperationStatus"] == "FAILED", f"unexpected final status: {final}"
        assert final.get("ErrorCode") == "InvalidRequest", f"unexpected ErrorCode: {final}"

    # Effect absent: no queue was created despite the unknown property.
    lookup_code, lookup_message = _error_code(lambda: sqs.get_queue_url(QueueName=bad_queue_name))
    assert lookup_code == "AWS.SimpleQueueService.NonExistentQueue"
    assert lookup_message == "The specified queue does not exist.", lookup_message

    # Positive control: the same request without the unknown property succeeds.
    good_queue_name = ctx.unique_name("sim2real-behav-ccextra-good-")
    good_desired_state = json.dumps({"QueueName": good_queue_name})
    progress = cc.create_resource(
        TypeName="AWS::SQS::Queue", DesiredState=good_desired_state
    )["ProgressEvent"]
    ctx.on_cleanup(
        lambda: sqs.delete_queue(QueueUrl=sqs.get_queue_url(QueueName=good_queue_name)["QueueUrl"])
    )
    final = _poll_request_status(ctx, progress["RequestToken"])
    assert final["OperationStatus"] == "SUCCESS", f"control create failed: {final}"

    # Terminal read is independent of CloudControl's own bookkeeping: the queue must be
    # visible, with the right identity, through SQS's own API -- not just a SUCCESS status
    # word from GetResourceRequestStatus.
    good_queue_url = sqs.get_queue_url(QueueName=good_queue_name)["QueueUrl"]
    good_arn = sqs.get_queue_attributes(
        QueueUrl=good_queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]
    assert good_arn.endswith(good_queue_name), f"unexpected queue arn: {good_arn}"


def _error_code(fn):
    try:
        result = fn()
    except botocore.exceptions.ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _delete_queue_if_exists(sqs, queue_name: str) -> None:
    try:
        url = sqs.get_queue_url(QueueName=queue_name)["QueueUrl"]
        sqs.delete_queue(QueueUrl=url)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "AWS.SimpleQueueService.NonExistentQueue",
            "QueueDoesNotExist",
        ):
            raise


def _poll_request_status(ctx, token, timeout_s=120.0, interval_s=3.0):
    cc = ctx.client("cloudcontrol")
    deadline = time.monotonic() + timeout_s
    terminal = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
    last = None
    while time.monotonic() < deadline:
        last = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
        if last["OperationStatus"] in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {token} never reached a terminal status; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
