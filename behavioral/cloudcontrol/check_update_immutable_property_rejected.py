"""update-immutable-property-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-immutable-property-rejected"
GROUP = "e2e"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A patch replacing a FIFO queue's create-only FifoQueue is refused with NotUpdatableException
    and the exact createOnlyProperties diagnostic and FifoQueue stays True, while a patch of
    VisibilityTimeout to 77 on the same queue succeeds."""
    cc = ctx.client("cloudcontrol")
    teardown = _Teardown()

    queue_name = ctx.unique_name("sim2real-cc-immut-") + ".fifo"
    desired_state = json.dumps(
        {
            "QueueName": queue_name,
            "FifoQueue": True,
            "ContentBasedDeduplication": True,
            "VisibilityTimeout": 30,
            "Tags": [{"Key": "sim2real", "Value": CHECK}],
        }
    )
    create_resp = cc.create_resource(TypeName="AWS::SQS::Queue", DesiredState=desired_state)
    create_event = _wait_for_progress(cc, create_resp["ProgressEvent"]["RequestToken"])
    assert create_event["OperationStatus"] == "SUCCESS", create_event
    queue_url = create_event["Identifier"]
    ctx.on_cleanup(lambda: _delete_resource(cc, "AWS::SQS::Queue", queue_url, teardown))

    # Break exactly one thing: try to flip the create-only FifoQueue property.
    bad_patch = json.dumps([{"op": "replace", "path": "/FifoQueue", "value": False}])
    code, message = _error(
        lambda: cc.update_resource(
            TypeName="AWS::SQS::Queue", Identifier=queue_url, PatchDocument=bad_patch
        )
    )
    assert code == "NotUpdatableException", f"expected NotUpdatableException, got {code}"
    expected = "Invalid patch update: createOnlyProperties [/properties/FifoQueue] cannot be updated"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the property must remain unchanged.
    props = _get_properties(cc, "AWS::SQS::Queue", queue_url)
    assert props["FifoQueue"] is True, f"expected FifoQueue to remain True, got {props.get('FifoQueue')!r}"

    # Positive control: a mutable property update on the SAME resource still works.
    good_patch = json.dumps([{"op": "replace", "path": "/VisibilityTimeout", "value": 77}])
    update_resp = cc.update_resource(
        TypeName="AWS::SQS::Queue", Identifier=queue_url, PatchDocument=good_patch
    )
    update_event = _wait_for_progress(cc, update_resp["ProgressEvent"]["RequestToken"])
    assert update_event["OperationStatus"] == "SUCCESS", update_event
    props_after = _get_properties(cc, "AWS::SQS::Queue", queue_url)
    assert props_after["VisibilityTimeout"] == 77, (
        f"expected VisibilityTimeout=77 after the control update, got {props_after.get('VisibilityTimeout')!r}"
    )


def _wait_for_progress(cc, request_token: str, timeout_s: float = 180.0, interval_s: float = 2.0) -> dict:
    terminal = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]
        if last.get("OperationStatus") in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {request_token} did not reach a terminal state; last={last}")


def _get_properties(cc, type_name: str, identifier: str) -> dict:
    resp = cc.get_resource(TypeName=type_name, Identifier=identifier)
    return json.loads(resp["ResourceDescription"]["Properties"])


def _error(fn) -> tuple[str, str]:
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
