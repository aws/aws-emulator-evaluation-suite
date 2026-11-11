"""update-during-in-progress-create-conflict."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-during-in-progress-create-conflict"
GROUP = "concurrency"
SERVICES = ["cloudcontrol"]

_TERMINAL = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateResource of a queue whose CreateResource is still in progress is refused with
    ConcurrentOperationException naming the queue and the create's RequestToken and changes nothing;
    the same update after the create settles succeeds and sets VisibilityTimeout to 45."""
    cc = ctx.client("cloudcontrol")
    teardown = _Teardown()
    queue_name = ctx.unique_name("sim2real-cc-updconf-")
    type_name = "AWS::SQS::Queue"

    create_resp = cc.create_resource(
        TypeName=type_name, DesiredState=json.dumps({"QueueName": queue_name})
    )
    token = create_resp["ProgressEvent"]["RequestToken"]
    identifier = create_resp["ProgressEvent"].get("Identifier")

    patch = json.dumps([{"op": "add", "path": "/VisibilityTimeout", "value": 45}])
    conflict_code = conflict_message = None
    last_status = create_resp["ProgressEvent"]["OperationStatus"]

    # Tight, un-slept polling loop: race an UpdateResource against the CREATE
    # while it is still PENDING/IN_PROGRESS on the same identifier.
    for _ in range(30):
        if last_status in _TERMINAL:
            break
        status_event = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
        last_status = status_event["OperationStatus"]
        identifier = identifier or status_event.get("Identifier")
        if last_status in _TERMINAL or identifier is None:
            continue
        try:
            cc.update_resource(TypeName=type_name, Identifier=identifier, PatchDocument=patch)
            break  # update was accepted -- create must have already finished; stop racing
        except ClientError as exc:
            conflict_code = exc.response["Error"]["Code"]
            conflict_message = exc.response["Error"].get("Message")
            break

    final = _poll_request_status(cc, token, timeout_s=90)
    assert final["OperationStatus"] == "SUCCESS", final
    identifier = final["Identifier"]
    ctx.on_cleanup(lambda: _delete_resource(cc, type_name, identifier, teardown))

    if conflict_code is None:
        raise AssertionError(
            "create completed before an UpdateResource could be raced against "
            "its IN_PROGRESS window"
        )
    assert conflict_code == "ConcurrentOperationException", conflict_code
    expected_conflict = f"Concurrent operation found for resource {identifier} with RequestToken {token}"
    assert conflict_message == expected_conflict, (
        f"expected message {expected_conflict!r}, got {conflict_message!r}"
    )

    # Effect-absent: the rejected UpdateResource must not have reached the
    # native queue despite the create now being stable -- read the property
    # directly rather than trusting the rejection alone.
    props_before = json.loads(
        cc.get_resource(TypeName=type_name, Identifier=identifier)["ResourceDescription"]["Properties"]
    )
    assert props_before.get("VisibilityTimeout") != 45, (
        f"rejected update leaked through despite ConcurrentOperationException: {props_before}"
    )

    # Positive control: the identical update succeeds once the create has
    # actually stabilized -- proving the earlier rejection was specifically
    # about the in-progress conflict, not the PatchDocument itself.
    update_resp = cc.update_resource(TypeName=type_name, Identifier=identifier, PatchDocument=patch)
    update_final = _poll_request_status(cc, update_resp["ProgressEvent"]["RequestToken"], timeout_s=90)
    assert update_final["OperationStatus"] == "SUCCESS", update_final

    # Terminal read is independent of both the mutating UpdateResource call and
    # the CloudControl status poll: read the queue's own property back and
    # confirm the patch actually landed on the native resource, not just that
    # CloudControl reported SUCCESS.
    props_after = json.loads(
        cc.get_resource(TypeName=type_name, Identifier=identifier)["ResourceDescription"]["Properties"]
    )
    assert props_after.get("VisibilityTimeout") == 45, (
        f"UpdateResource reported SUCCESS but native VisibilityTimeout is {props_after.get('VisibilityTimeout')!r}"
    )


def _poll_request_status(cc, token, timeout_s=90.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cc.get_resource_request_status(RequestToken=token)
        last = resp["ProgressEvent"]
        if last["OperationStatus"] in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {token} did not reach terminal state within {timeout_s}s: {last}")


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
