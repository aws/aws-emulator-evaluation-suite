"""create-resource-out-of-range-property-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-resource-out-of-range-property-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateResource with DelaySeconds=901 (schema range 0-900) terminates FAILED/InvalidRequest.

    No queue is created with a clamped value; in-range DelaySeconds=5 round-trips via GetResource.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-delay-queues.html
    """
    cc = ctx.client("cloudcontrol")
    sqs = ctx.client("sqs")

    bad_name = ctx.unique_name("sim2real-cc-oor-")
    resp = cc.create_resource(
        TypeName="AWS::SQS::Queue",
        DesiredState=json.dumps({"QueueName": bad_name, "DelaySeconds": 901}),
    )
    token = resp["ProgressEvent"]["RequestToken"]
    teardown = _Teardown()
    ctx.on_cleanup(lambda: _cleanup_request(cc, "AWS::SQS::Queue", token, teardown))
    final = _poll_request_status(cc, token, timeout_s=60.0)

    assert final["OperationStatus"] == "FAILED", f"unexpected status: {final}"
    assert final["ErrorCode"] == "InvalidRequest", f"unexpected error code: {final}"
    # message varies: StatusMessage embeds the downstream SQS Request ID

    listed = sqs.list_queues(QueueNamePrefix=bad_name).get("QueueUrls", [])
    assert listed == [], f"queue was created despite out-of-range DelaySeconds: {listed}"

    # positive control: the same property within range succeeds and the value round-trips
    good_name = ctx.unique_name("sim2real-cc-inrange-")
    good_resp = cc.create_resource(
        TypeName="AWS::SQS::Queue",
        DesiredState=json.dumps(
            {"QueueName": good_name, "DelaySeconds": 5, "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ),
    )
    good_token = good_resp["ProgressEvent"]["RequestToken"]
    ctx.on_cleanup(lambda: _cleanup_request(cc, "AWS::SQS::Queue", good_token, teardown))
    good_final = _poll_request_status(cc, good_token, timeout_s=150.0)
    assert good_final["OperationStatus"] == "SUCCESS", f"control failed: {good_final}"
    identifier = good_final["Identifier"]

    props = json.loads(cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=identifier)[
        "ResourceDescription"
    ]["Properties"])
    assert int(props["DelaySeconds"]) == 5, f"unexpected DelaySeconds: {props}"


def _poll_request_status(cc: Any, request_token: str, timeout_s: float = 90.0) -> dict:
    terminal = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]
        if last.get("OperationStatus") in terminal:
            return last
        time.sleep(2.0)
    raise AssertionError(f"request never reached a terminal state: {last}")


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


def _cleanup_request(cc, type_name: str, token: str, teardown) -> None:
    """Wait for a create request to end, then delete the resource it made."""
    event = _request_outcome(cc, token, teardown)
    if event["OperationStatus"] == "SUCCESS":
        _delete_resource(cc, type_name, event["Identifier"], teardown)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
