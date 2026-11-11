"""server-side-rollback-on-create-failure-no-partial-resource."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-rollback-on-create-failure-no-partial-resource"
GROUP = "server-side"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A FIFO queue CreateResource whose name lacks ".fifo" passes schema validation but ends FAILED
    with GeneralServiceException and a FIFO-suffix StatusMessage, leaving no queue in Cloud Control
    or SQS, while the same create with a ".fifo" name succeeds."""
    cc = ctx.client("cloudcontrol")
    teardown = _Teardown()
    sqs = ctx.client("sqs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # Positive control: a schema-valid, cross-field-consistent FIFO queue must actually succeed
    # end to end -- through Cloud Control's own async lifecycle and confirmed by a native SQS
    # read -- before the negative below can mean anything.
    control_name = ctx.unique_name("sim2real-cc-goodfifo-") + ".fifo"
    control_identifier = f"{sqs.meta.endpoint_url}/{account_id}/{control_name}"
    ctx.on_cleanup(lambda: _delete_resource(cc, "AWS::SQS::Queue", control_identifier, teardown))
    control_resp = cc.create_resource(
        TypeName="AWS::SQS::Queue",
        DesiredState=json.dumps({"QueueName": control_name, "FifoQueue": True}),
    )
    control_final = _poll_request_status(cc, control_resp["ProgressEvent"]["RequestToken"], timeout_s=90.0, interval_s=2.0)
    assert control_final["OperationStatus"] == "SUCCESS", (
        f"positive control: a schema-valid FIFO queue create must succeed, got {control_final}"
    )
    control_url = sqs.get_queue_url(QueueName=control_name)["QueueUrl"]
    assert control_url, "positive control queue does not resolve via a native SQS GetQueueUrl"

    # A FIFO queue name MUST end in ".fifo" -- SQS's own JSON schema for QueueName doesn't
    # encode that cross-field constraint, so Cloud Control accepts the request and hands it to
    # the SQS resource handler, which fails only when it actually calls CreateQueue.
    name = ctx.unique_name("sim2real-cc-badfifo-")
    assert not name.endswith(".fifo")

    create_resp = cc.create_resource(
        TypeName="AWS::SQS::Queue",
        DesiredState=json.dumps({"QueueName": name, "FifoQueue": True}),
    )
    token = create_resp["ProgressEvent"]["RequestToken"]

    final = _poll_request_status(cc, token, timeout_s=90.0, interval_s=2.0)
    assert final["OperationStatus"] == "FAILED", f"expected the mismatched FIFO create to FAIL, got {final}"
    # SQS's FIFO-naming validation is a plain 400 with no typed exception, so the handler reports
    # it under the catch-all GeneralServiceException; the StatusMessage names the violation.
    assert final.get("ErrorCode") == "GeneralServiceException", (
        f"expected the downstream SQS handler's rejection to surface as "
        f"ErrorCode='GeneralServiceException', got {final}"
    )
    # message varies: the StatusMessage embeds the downstream SQS Request ID.
    message = final.get("StatusMessage") or ""
    assert ".fifo" in message and "FIFO" in message, (
        f"the StatusMessage does not carry the downstream handler's own FIFO-suffix diagnosis: {message!r}"
    )

    would_be_url = f"{sqs.meta.endpoint_url}/{account_id}/{name}"

    # message varies: Cloud Control embeds the server-minted RequestToken of its own handler
    # invocation, which no response returns.
    get_code, _ = _error(
        lambda: cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=would_be_url)
    )
    assert get_code == "ResourceNotFoundException", (
        f"expected no partial resource to exist after the rolled-back create, got GetResource code {get_code!r}"
    )

    # Confirm directly against SQS (bypassing Cloud Control) that the queue truly was never
    # created -- this is the ground truth the rollback claim depends on.
    sqs_code, sqs_message = _error(lambda: sqs.get_queue_url(QueueName=name))
    assert sqs_code == "AWS.SimpleQueueService.NonExistentQueue", (
        f"expected SQS itself to have no record of the queue, got {sqs_code!r}"
    )
    assert sqs_message == "The specified queue does not exist.", (
        f"unexpected NonExistentQueue message: {sqs_message!r}"
    )


def _poll_request_status(cc: Any, token: str, *, timeout_s: float, interval_s: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        resp = cc.get_resource_request_status(RequestToken=token)
        last = resp["ProgressEvent"]
        if last["OperationStatus"] in ("SUCCESS", "FAILED", "CANCEL_COMPLETE"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {token} never reached a terminal state in {timeout_s}s: {last}")


def _error(fn: Any) -> tuple[str, str]:
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so a
    target that accepts what AWS refuses is never read as a plain code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


#: Seconds every teardown of one run shares: the suite's 900 s cleanup budget less a 120 s margin.
_CLEANUP_S = 780.0


class _Teardown:
    """One deadline for all of a run's teardowns, started when the first of them runs."""

    def __init__(self) -> None:
        self._at = None

    def deadline(self) -> float:
        if self._at is None:
            self._at = time.monotonic() + _CLEANUP_S
        return self._at


def _request_outcome(cc, token: str, teardown) -> dict:
    """Poll GetResourceRequestStatus every 2 s until the request ends; return its ProgressEvent."""
    while True:
        event = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
        if event["OperationStatus"] not in ("PENDING", "IN_PROGRESS", "CANCEL_IN_PROGRESS"):
            return event
        if time.monotonic() >= teardown.deadline():
            raise AssertionError(
                f"request {token} is still {event['OperationStatus']} at the cleanup deadline"
            )
        time.sleep(2)


def _delete_resource(cc, type_name: str, identifier: str, teardown) -> None:
    """DeleteResource and wait for its outcome; a NotFound answer means the resource is gone.

    ConcurrentOperationException and ResourceConflictException (another request holds the
    resource) are retried every 2 s to the shared cleanup deadline; anything else raises."""
    while True:
        try:
            resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code not in ("ConcurrentOperationException", "ResourceConflictException"):
                raise
            if time.monotonic() >= teardown.deadline():
                raise
            time.sleep(2)
    event = _request_outcome(cc, resp["ProgressEvent"]["RequestToken"], teardown)
    if event["OperationStatus"] == "FAILED" and event.get("ErrorCode") == "NotFound":
        return
    if event["OperationStatus"] != "SUCCESS":
        raise AssertionError(
            f"DeleteResource of {type_name} {identifier} ended {event['OperationStatus']}: {event}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
