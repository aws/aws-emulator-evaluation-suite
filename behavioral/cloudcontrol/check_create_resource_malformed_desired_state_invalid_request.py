"""create-resource-malformed-desired-state-invalid-request."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}

HANDLER_ERROR_TO_EXCEPTION = {
    "AlreadyExists": "AlreadyExistsException",
    "NotFound": "ResourceNotFoundException",
    "NotUpdatable": "NotUpdatableException",
    "InvalidRequest": "InvalidRequestException",
    "ResourceConflict": "ResourceConflictException",
    "NotStabilized": "NotStabilizedException",
    "ServiceLimitExceeded": "ServiceLimitExceededException",
    "Throttling": "ThrottlingException",
    "AccessDenied": "AccessDeniedException",
    "InternalFailure": "HandlerInternalFailureException",
    "GeneralServiceException": "GeneralServiceException",
    "ServiceInternalError": "ServiceInternalErrorException",
    "NetworkFailure": "NetworkFailureException",
    "UnsupportedTarget": "UnsupportedActionException",
    "InvalidCredentials": "InvalidCredentialsException",
}

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

def _wait_terminal(cc, request_token, timeout_s=90, interval_s=2):
    """Poll GetResourceRequestStatus until the request reaches a terminal
    OperationStatus. Returns the final ProgressEvent dict."""
    holder = {}

    def probe():
        resp = cc.get_resource_request_status(RequestToken=request_token)
        holder["event"] = resp["ProgressEvent"]
        return holder["event"]

    _poll_until(
        probe,
        lambda e: e is not None and e.get("OperationStatus") in TERMINAL_STATUSES,
        timeout_s=timeout_s,
        interval_s=interval_s,
    )
    return holder["event"]

def _get_resource(cc, type_name, identifier):
    return cc.get_resource(TypeName=type_name, Identifier=identifier)

def _failure(cc, call):
    """Invoke a call expected to be refused; return its canonical exception-style (code, message),
    whether refused synchronously (ClientError) or via a terminal FAILED ProgressEvent
    (ErrorCode mapped to its exception name, StatusMessage). An unexpected success raises."""
    try:
        resp = call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    event = resp.get("ProgressEvent")
    if event is None:
        raise AssertionError(f"expected the call to be refused, but it succeeded and returned {resp!r}")
    event = _wait_terminal(cc, event["RequestToken"])
    status = event.get("OperationStatus")
    assert status == "FAILED", (
        f"operation was expected to be refused but reached {status}: {event}"
    )
    handler_code = event.get("ErrorCode")
    return HANDLER_ERROR_TO_EXCEPTION.get(handler_code, handler_code), event.get("StatusMessage")

CHECK = "create-resource-malformed-desired-state-invalid-request"
GROUP = 'error-semantics'
SERVICES = ['cloudcontrol']
SSM_PARAM_TYPE = "AWS::SSM::Parameter"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateResource of an AWS::SSM::Parameter without the required Value fails synchronously with ValidationException
    and the exact schema message and leaves no resource, while a complete DesiredState of the same type succeeds."""
    cc = ctx.client("cloudcontrol")
    control_name = ctx.unique_name("sim2real-behav-cc-param-ctrl-")
    name = ctx.unique_name("sim2real-behav-cc-param-")

    good_state = json.dumps({
        "Name": control_name, "Type": "String", "Value": "sim2real-behav-value",
        "Tags": {"sim2real": CHECK},
    })
    resp = cc.create_resource(TypeName=SSM_PARAM_TYPE, DesiredState=good_state)
    teardown = _Teardown()
    ctx.on_cleanup(lambda: _delete_resource(cc, SSM_PARAM_TYPE, control_name, teardown))
    control_final = _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"])
    assert control_final.get("OperationStatus") == "SUCCESS", (
        f"positive control create failed, cannot attribute the rejection below: {control_final!r}"
    )
    assert _get_resource(cc, SSM_PARAM_TYPE, control_name)["ResourceDescription"]["Identifier"] == control_name, (
        "positive control resource is not visible via an independent GetResource"
    )

    bad_state = json.dumps({"Name": name, "Type": "String"})  # missing required "Value"
    code, message = _failure(cc,
        lambda: cc.create_resource(TypeName=SSM_PARAM_TYPE, DesiredState=bad_state)
    )
    # Cloud Control validates DesiredState against the registry
    # schema synchronously and raises ValidationException (NOT the modeled
    # InvalidRequestException, which is reserved for handler-reported errors).
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = "Model validation failed (#: required key [Value] not found)"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    not_found_code, _ = _failure(cc, lambda: _get_resource(cc, SSM_PARAM_TYPE, name))
    assert not_found_code == "ResourceNotFoundException", (
        f"malformed create should not have left a resource behind, got {not_found_code}"
    )
    # message varies: GetResource's NotFound message embeds the RequestToken of the internal read-handler call, which the caller never receives


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
