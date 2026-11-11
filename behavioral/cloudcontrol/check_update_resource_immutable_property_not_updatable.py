"""update-resource-immutable-property-not-updatable."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

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

def _track(cc, ctx, type_name, identifier, teardown):
    ctx.on_cleanup(lambda: _delete_resource(cc, type_name, identifier, teardown))

def _create_and_wait(cc, ctx, type_name, desired_state, client_token=None, track=True, *, teardown):
    """CreateResource and wait for a terminal state; track the identifier for
    cleanup on success. Returns the final ProgressEvent."""
    kwargs = {"TypeName": type_name, "DesiredState": desired_state}
    if client_token:
        kwargs["ClientToken"] = client_token
    resp = cc.create_resource(**kwargs)
    event = _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"])
    if track and event.get("OperationStatus") == "SUCCESS":
        identifier = event.get("Identifier")
        if identifier:
            _track(cc, ctx, type_name, identifier, teardown)
    return event

def _get_resource(cc, type_name, identifier):
    return cc.get_resource(TypeName=type_name, Identifier=identifier)

def _failure_outcome(cc, call):
    """Invoke a mutating call expected to be refused; return (sync_error, terminal_event)
    with exactly one element non-None. sync_error is the ClientError's (code, message)."""
    try:
        resp = call()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return (error.get("Code"), error.get("Message", "")), None
    return None, _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"])

def _normalized_failure(cc, call):
    """Canonical exception-style (code, message) for a call expected to fail, whether refused
    synchronously or via a terminal FAILED ProgressEvent (ErrorCode, StatusMessage)."""
    error, event = _failure_outcome(cc, call)
    if error is not None:
        return error
    status = event.get("OperationStatus")
    assert status == "FAILED", (
        f"operation was expected to be refused but reached {status}: {event}"
    )
    handler_code = event.get("ErrorCode")
    return HANDLER_ERROR_TO_EXCEPTION.get(handler_code, handler_code), event.get("StatusMessage", "")

def _ssm_desired_state(name, value="v1", ptype="String"):
    return json.dumps({"Name": name, "Type": ptype, "Value": value})

CHECK = "update-resource-immutable-property-not-updatable"
GROUP = 'error-semantics'
SERVICES = ['cloudcontrol']
SSM_PARAM_TYPE = "AWS::SSM::Parameter"

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A patch replacing an SSM parameter's create-only /Name is refused with NotUpdatableException and
    the exact createOnlyProperties diagnostic and leaves Value "orig", while a patch of Value to "v2"
    on the same parameter succeeds."""
    cc = ctx.client("cloudcontrol")
    teardown = _Teardown()
    name = ctx.unique_name("sim2real-behav-cc-param-")
    create_event = _create_and_wait(cc, ctx, SSM_PARAM_TYPE, _ssm_desired_state(name, value="orig"), teardown=teardown)
    assert create_event["OperationStatus"] == "SUCCESS", f"expected CreateResource to succeed, got {create_event}"

    other_name = ctx.unique_name("sim2real-behav-cc-param-")
    patch = json.dumps([{"op": "replace", "path": "/Name", "value": other_name}])
    code, message = _normalized_failure(cc,
        lambda: cc.update_resource(TypeName=SSM_PARAM_TYPE, Identifier=name, PatchDocument=patch)
    )
    assert code == "NotUpdatableException", f"expected NotUpdatableException, got {code}"
    expected = "Invalid patch update: createOnlyProperties [/properties/Name] cannot be updated"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # original resource must still be present and unchanged
    resp = _get_resource(cc, SSM_PARAM_TYPE, name)
    props = json.loads(resp["ResourceDescription"]["Properties"])
    assert props.get("Value") == "orig", (
        f"expected Value to remain 'orig' after the rejected Name update, got {props.get('Value')!r}"
    )

    # positive control: a mutable property (Value) update on the SAME resource still succeeds
    update_resp = cc.update_resource(
        TypeName=SSM_PARAM_TYPE,
        Identifier=name,
        PatchDocument=json.dumps([{"op": "replace", "path": "/Value", "value": "v2"}]),
    )
    update_event = _wait_terminal(cc, update_resp["ProgressEvent"]["RequestToken"])
    assert update_event["OperationStatus"] == "SUCCESS", (
        f"expected mutable Value update to succeed, got {update_event}"
    )
    resp2 = _get_resource(cc, SSM_PARAM_TYPE, name)
    props2 = json.loads(resp2["ResourceDescription"]["Properties"])
    assert props2.get("Value") == "v2", (
        f"expected Value='v2' after the positive-control update, got {props2.get('Value')!r}"
    )


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
