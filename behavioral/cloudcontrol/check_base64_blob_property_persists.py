"""base64-blob-property-persists."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "base64-blob-property-persists"
GROUP = "representation"
SERVICES = ["cloudcontrol"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An SSM Parameter Value holding the base64 of bytes 0-255 round-trips through CreateResource and
    GetResource to identical bytes, and after DeleteResource GetResource fails with ResourceNotFoundException
    and the handler's exact message."""
    cc = ctx.client("cloudcontrol")
    teardown = _Teardown()

    raw_bytes = bytes(range(256))
    encoded = base64.b64encode(raw_bytes).decode("ascii")

    param_name = ctx.unique_name("sim2real-cc-b64")
    desired_state = json.dumps(
        {
            "Name": param_name,
            "Type": "String",
            "Value": encoded,
            "Tags": {"sim2real": CHECK},
        }
    )
    create_resp = cc.create_resource(TypeName="AWS::SSM::Parameter", DesiredState=desired_state)
    token = create_resp["ProgressEvent"]["RequestToken"]
    ctx.on_cleanup(lambda: _cleanup_request(cc, "AWS::SSM::Parameter", token, teardown))
    event = _wait_for_progress(cc, token)
    assert event["OperationStatus"] == "SUCCESS", event
    identifier = event["Identifier"]

    props = _get_properties(cc, "AWS::SSM::Parameter", identifier)
    returned_b64 = props["Value"]
    decoded = base64.b64decode(returned_b64)
    assert decoded == raw_bytes, "decoded Value bytes differ from what was written"

    delete_resp = cc.delete_resource(TypeName="AWS::SSM::Parameter", Identifier=identifier)
    delete_event = _wait_for_progress(cc, delete_resp["ProgressEvent"]["RequestToken"])
    assert delete_event["OperationStatus"] == "SUCCESS", delete_event

    try:
        cc.get_resource(TypeName="AWS::SSM::Parameter", Identifier=identifier)
        raise AssertionError(f"expected {identifier} to be gone after delete, but get_resource succeeded")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"]["Message"]
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {code!r}"
    expected = _handler_not_found("AWS::SSM::Parameter", identifier, message)
    assert message == expected, f"expected message {expected!r}, got {message!r}"


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


def _handler_not_found(type_name: str, identifier: str, message: str) -> str:
    """The handler's NotFound text; its RequestToken is minted per call, so it is read back."""
    token = message.rpartition("RequestToken: ")[2].removesuffix(")")
    return (
        f"{type_name} Handler returned status FAILED: Resource of type '{type_name}' with "
        f"identifier '{identifier}' was not found. (HandlerErrorCode: NotFound, RequestToken: {token})"
    )


def _get_properties(cc, type_name: str, identifier: str) -> dict:
    resp = cc.get_resource(TypeName=type_name, Identifier=identifier)
    return json.loads(resp["ResourceDescription"]["Properties"])


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
