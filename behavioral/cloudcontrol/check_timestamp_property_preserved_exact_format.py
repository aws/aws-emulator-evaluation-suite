"""timestamp-property-preserved-exact-format."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "timestamp-property-preserved-exact-format"
GROUP = "representation"
SERVICES = ["cloudcontrol"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An ISO-8601 extended StartDate string (with fractional seconds and a Z suffix) is stored and returned
    with the exact same string representation -- no timezone normalization or precision loss. The window
    is then deleted and proven gone via an independent GetResource."""
    cc = ctx.client("cloudcontrol")
    teardown = _Teardown()
    mw_name = ctx.unique_name("sim2real-behav-cc-ts-")
    start_date = "2030-06-15T10:30:45.123Z"
    desired_state = json.dumps(
        {
            "Name": mw_name,
            "Schedule": "rate(7 days)",
            "Duration": 2,
            "Cutoff": 1,
            "AllowUnassociatedTargets": False,
            "StartDate": start_date,
            "Tags": [{"Key": "sim2real", "Value": mw_name}],
        }
    )
    resp = cc.create_resource(TypeName="AWS::SSM::MaintenanceWindow", DesiredState=desired_state)
    event = _wait_for_progress(ctx, resp["ProgressEvent"]["RequestToken"])
    assert event["OperationStatus"] == "SUCCESS", event
    identifier = event["Identifier"]
    ctx.on_cleanup(lambda: _delete_resource(cc, "AWS::SSM::MaintenanceWindow", identifier, teardown))

    got = cc.get_resource(TypeName="AWS::SSM::MaintenanceWindow", Identifier=identifier)
    props = json.loads(got["ResourceDescription"]["Properties"])
    assert props["StartDate"] == start_date, (
        f"StartDate drifted: got {props['StartDate']!r}, expected {start_date!r}"
    )

    delete_resp = cc.delete_resource(TypeName="AWS::SSM::MaintenanceWindow", Identifier=identifier)
    delete_event = _wait_for_progress(ctx, delete_resp["ProgressEvent"]["RequestToken"])
    assert delete_event["OperationStatus"] == "SUCCESS", delete_event

    code, message = _error(lambda: cc.get_resource(TypeName="AWS::SSM::MaintenanceWindow", Identifier=identifier))
    assert code == "ResourceNotFoundException", code
    expected = _handler_not_found(
        message,
        "AWS::SSM::MaintenanceWindow Handler returned status FAILED: Resource of type "
        f"'AWS::SSM::MaintenanceWindow' with identifier '{identifier}' was not found.",
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so a
    target that accepts what AWS refuses is never read as a plain code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


#: A RequestToken: a lowercase UUID.
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


def _handler_not_found(message, detail):
    """The handler's NotFound text; its RequestToken (a UUID) is minted per call, so it is read back."""
    token = message.rpartition("RequestToken: ")[2].removesuffix(")")
    token = token if re.fullmatch(_UUID, token) else "<a UUID>"
    return f"{detail} (HandlerErrorCode: NotFound, RequestToken: {token})"


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
