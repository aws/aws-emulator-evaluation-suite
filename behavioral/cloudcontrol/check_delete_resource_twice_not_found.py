"""delete-resource-twice-not-found."""
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

def _delete_quiet(cc, type_name, identifier):
    try:
        resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
        _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"], timeout_s=60, interval_s=2)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "RequestTokenNotFoundException",
            "ResourceNotFoundException",
            "TypeNotFoundException",
        ):
            raise

def _track(cc, ctx, type_name, identifier):
    ctx.on_cleanup(lambda: _delete_quiet(cc, type_name, identifier))

def _create_and_wait(cc, ctx, type_name, desired_state, client_token=None, track=True):
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
            _track(cc, ctx, type_name, identifier)
    return event

def _delete_and_wait(cc, type_name, identifier, client_token=None):
    kwargs = {"TypeName": type_name, "Identifier": identifier}
    if client_token:
        kwargs["ClientToken"] = client_token
    resp = cc.delete_resource(**kwargs)
    return _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"])


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

def _ssm_desired_state(name, value="v1", ptype="String"):
    return json.dumps({"Name": name, "Type": ptype, "Value": value})

CHECK = "delete-resource-twice-not-found"
GROUP = 'overly-permissive'
SERVICES = ['cloudcontrol']
SSM_PARAM_TYPE = "AWS::SSM::Parameter"

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """[overly-permissive] Deleting an already-deleted resource must fail with
    ResourceNotFoundException, not silently succeed, and the resource must remain
    genuinely absent (not resurrected) afterward."""
    cc = ctx.client("cloudcontrol")
    name = ctx.unique_name("sim2real-behav-cc-param-")
    create_event = _create_and_wait(cc, ctx, SSM_PARAM_TYPE, _ssm_desired_state(name))
    assert create_event["OperationStatus"] == "SUCCESS"

    first_delete = _delete_and_wait(cc, SSM_PARAM_TYPE, name)
    assert first_delete["OperationStatus"] == "SUCCESS"

    code, message = _failure(cc,
        lambda: cc.delete_resource(TypeName=SSM_PARAM_TYPE, Identifier=name)
    )
    assert code == "ResourceNotFoundException", (
        f"second delete of an already-deleted resource must fail, got {code}"
    )
    expected_message = f"Resource of type '{SSM_PARAM_TYPE}' with identifier '{name}' was not found."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    gone_code, _ = _failure(cc, lambda: _get_resource(cc, SSM_PARAM_TYPE, name))
    assert gone_code == "ResourceNotFoundException", (
        f"the resource must still be genuinely gone after the rejected second delete, got {gone_code}"
    )
    # message varies: GetResource's NotFound message embeds the RequestToken of the internal read-handler call, which the caller never receives

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
