"""e2e-create-update-observe-delete-flow."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-create-update-observe-delete-flow"
GROUP = "e2e"
SERVICES = ["cloudcontrol"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A queue created through Cloud Control reads back VisibilityTimeout 30, then 60 after an update;
    once deleted, GetResource and UpdateResource are both refused with ResourceNotFoundException."""
    cc = ctx.client("cloudcontrol")
    teardown = _Teardown()
    queue_name = ctx.unique_name("sim2real-behav-cc-e2e-")
    desired_state = json.dumps(
        {"QueueName": queue_name, "VisibilityTimeout": 30, "Tags": [{"Key": "sim2real", "Value": CHECK}]}
    )

    create_resp = cc.create_resource(TypeName="AWS::SQS::Queue", DesiredState=desired_state)
    create_event = _wait_for_progress(ctx, create_resp["ProgressEvent"]["RequestToken"])
    assert create_event["OperationStatus"] == "SUCCESS", create_event
    identifier = create_event["Identifier"]
    ctx.on_cleanup(lambda: _delete_resource(cc, "AWS::SQS::Queue", identifier, teardown))

    got = cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=identifier)
    props = json.loads(got["ResourceDescription"]["Properties"])
    assert props["VisibilityTimeout"] == 30, props.get("VisibilityTimeout")

    patch = json.dumps([{"op": "replace", "path": "/VisibilityTimeout", "value": 60}])
    update_resp = cc.update_resource(TypeName="AWS::SQS::Queue", Identifier=identifier, PatchDocument=patch)
    update_event = _wait_for_progress(ctx, update_resp["ProgressEvent"]["RequestToken"])
    assert update_event["OperationStatus"] == "SUCCESS", update_event

    got2 = cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=identifier)
    props2 = json.loads(got2["ResourceDescription"]["Properties"])
    assert props2["VisibilityTimeout"] == 60, "updated property was not observed as a consequence via GetResource"

    delete_resp = cc.delete_resource(TypeName="AWS::SQS::Queue", Identifier=identifier)
    delete_event = _wait_for_progress(ctx, delete_resp["ProgressEvent"]["RequestToken"])
    assert delete_event["OperationStatus"] == "SUCCESS", delete_event

    code, message = _error_code(lambda: cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=identifier))
    assert code == "ResourceNotFoundException", code
    expected = _handler_not_found(message, _queue_not_found_detail(identifier))
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    post_delete_patch = json.dumps([{"op": "replace", "path": "/VisibilityTimeout", "value": 90}])
    # AWS refuses it synchronously.
    post_delete_code, post_delete_message = _error_code(
        lambda: cc.update_resource(
            TypeName="AWS::SQS::Queue", Identifier=identifier, PatchDocument=post_delete_patch
        )
    )
    assert post_delete_code == "ResourceNotFoundException", (
        f"UpdateResource against the just-deleted identifier must be refused as not-found, got {post_delete_code}"
    )
    expected = _handler_not_found(post_delete_message, _queue_not_found_detail(identifier))
    assert post_delete_message == expected, f"expected message {expected!r}, got {post_delete_message!r}"


def _error_code(fn):
    """The error code and message fn() is refused with. An unexpected SUCCESS raises, so a target that
    serves what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a refusal, but the call SUCCEEDED and returned {result!r}")


#: A RequestToken: a lowercase UUID.
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


def _handler_not_found(message, detail):
    """The handler's NotFound text; its RequestToken (a UUID) is minted per call, so it is read back."""
    token = message.rpartition("RequestToken: ")[2].removesuffix(")")
    token = token if re.fullmatch(_UUID, token) else "<a UUID>"
    return f"{detail} (HandlerErrorCode: NotFound, RequestToken: {token})"


def _queue_not_found_detail(queue_url):
    return (
        "AWS::SQS::Queue Handler returned status FAILED: Resource of type 'AWS::SQS::Queue' "
        f"with identifier '{queue_url}' was not found."
    )


def _wait_for_progress(ctx, request_token, timeout_s=180.0, interval_s=2.0):
    cc = ctx.client("cloudcontrol")
    deadline = time.monotonic() + timeout_s
    event = None
    while time.monotonic() < deadline:
        event = cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]
        if event["OperationStatus"] in ("SUCCESS", "FAILED", "CANCEL_COMPLETE"):
            return event
        time.sleep(interval_s)
    raise AssertionError(f"operation did not stabilize within {timeout_s}s, last event={event}")


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
