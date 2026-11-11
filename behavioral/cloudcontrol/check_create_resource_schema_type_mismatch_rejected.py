"""create-resource-schema-type-mismatch-rejected."""
from __future__ import annotations

import json
import time

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-resource-schema-type-mismatch-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Supplying a string for a schema-typed integer property (SQS Queue
    DelaySeconds) is rejected synchronously with ValidationException, distinct
    from malformed-JSON and unknown-property checks."""
    cc = ctx.client("cloudcontrol")
    sqs = ctx.client("sqs")

    bad_queue_name = ctx.unique_name("sim2real-behav-cctype-bad-")
    bad_desired_state = json.dumps({"QueueName": bad_queue_name, "DelaySeconds": "many"})

    ctx.on_cleanup(lambda: _delete_queue_if_exists(sqs, bad_queue_name))
    code, message = _error(
        lambda: cc.create_resource(TypeName="AWS::SQS::Queue", DesiredState=bad_desired_state)
    )
    assert code == "ValidationException", f"unexpected error code: {code}"
    expected_message = (
        "Model validation failed (#/DelaySeconds: expected type: Integer, found: String. This may occur "
        "when a numeric value exceeds 32-bit integer max (2147483647). Consider using 'number' type "
        "or ensure value fits in integer range.)"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the type-mismatched create never produced a queue.
    lookup_code, lookup_message = _error(lambda: sqs.get_queue_url(QueueName=bad_queue_name))
    assert lookup_code == "AWS.SimpleQueueService.NonExistentQueue", (
        f"a type-mismatched create must never produce a queue, got lookup code {lookup_code!r}"
    )
    expected_lookup_message = "The specified queue does not exist."
    assert lookup_message == expected_lookup_message, (
        f"expected message {expected_lookup_message!r}, got {lookup_message!r}"
    )

    # Positive control: an identical create with the correctly-typed integer succeeds.
    good_queue_name = ctx.unique_name("sim2real-behav-cctype-good-")
    good_desired_state = json.dumps({"QueueName": good_queue_name, "DelaySeconds": 5})
    progress = cc.create_resource(
        TypeName="AWS::SQS::Queue", DesiredState=good_desired_state
    )["ProgressEvent"]
    ctx.on_cleanup(
        lambda: sqs.delete_queue(QueueUrl=sqs.get_queue_url(QueueName=good_queue_name)["QueueUrl"])
    )
    final = _poll_request_status(ctx, progress["RequestToken"])
    assert final["OperationStatus"] == "SUCCESS", f"positive control create must succeed: {final}"

    # Independent destination read: the queue must actually carry the correctly-typed
    # integer, not merely report SUCCESS from Cloud Control's own progress event.
    queue_url = sqs.get_queue_url(QueueName=good_queue_name)["QueueUrl"]
    good_attrs = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["DelaySeconds"])[
        "Attributes"
    ]
    assert good_attrs["DelaySeconds"] == "5", (
        f"positive control queue must carry the correctly-typed DelaySeconds, got {good_attrs}"
    )


def _error(fn):
    """Call fn(); return its ClientError (Code, Message). An unexpected SUCCESS raises -- an
    over-permissive target accepting a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except botocore.exceptions.ClientError as err:
        e = err.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
