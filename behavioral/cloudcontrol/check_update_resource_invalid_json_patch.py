"""update-resource-invalid-json-patch."""
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

def _get_resource(cc, type_name, identifier):
    return cc.get_resource(TypeName=type_name, Identifier=identifier)

def _failure_outcome(cc, call):
    """Invoke a mutating call expected to be refused; return (sync_error, terminal_event)
    with exactly one element non-None. sync_error is the ClientError's (code, message)."""
    try:
        resp = call()
    except Exception as exc:  # noqa: BLE001 - botocore ClientError and friends
        error = getattr(exc, "response", {}).get("Error", {})
        if error.get("Code") is None:
            raise
        return (error["Code"], error.get("Message", "")), None
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
    return json.dumps({"Name": name, "Type": ptype, "Value": value, "Tags": {"sim2real": CHECK}})

CHECK = "update-resource-invalid-json-patch"
GROUP = 'error-semantics'
SERVICES = ['cloudcontrol']
SSM_PARAM_TYPE = "AWS::SSM::Parameter"

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateResource with a PatchDocument that is not valid JSON Patch syntax is rejected synchronously with ValidationException and leaves the resource unchanged, while a well-formed patch on the same resource still succeeds."""
    cc = ctx.client("cloudcontrol")
    name = ctx.unique_name("sim2real-behav-cc-param-")
    create_event = _create_and_wait(cc, ctx, SSM_PARAM_TYPE, _ssm_desired_state(name, value="stable"))
    assert create_event["OperationStatus"] == "SUCCESS", (
        f"positive control: create did not succeed: {create_event}"
    )

    malformed_patch = json.dumps({"not": "a-json-patch-array"})
    code, message = _normalized_failure(cc,
        lambda: cc.update_resource(
            TypeName=SSM_PARAM_TYPE, Identifier=name, PatchDocument=malformed_patch
        )
    )
    # PatchDocument shape is validated at the front door, so this surfaces as
    # ValidationException rather than the handler-level InvalidRequestException.
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = "Invalid PatchDocument: A JSONArray text must start with '[' at 1 [character 2 line 1]"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    resp = _get_resource(cc, SSM_PARAM_TYPE, name)
    props = json.loads(resp["ResourceDescription"]["Properties"])
    assert props.get("Value") == "stable", (
        f"malformed patch mutated the resource: expected Value='stable', got {props.get('Value')!r}"
    )

    good_patch = json.dumps([{"op": "replace", "path": "/Value", "value": "updated"}])
    good_resp = cc.update_resource(TypeName=SSM_PARAM_TYPE, Identifier=name, PatchDocument=good_patch)
    good_event = _wait_terminal(cc, good_resp["ProgressEvent"]["RequestToken"])
    assert good_event["OperationStatus"] == "SUCCESS", (
        f"positive control: well-formed patch did not succeed: {good_event}"
    )

    resp2 = _get_resource(cc, SSM_PARAM_TYPE, name)
    props2 = json.loads(resp2["ResourceDescription"]["Properties"])
    assert props2.get("Value") == "updated", (
        f"positive control: well-formed patch did not take effect: expected Value='updated', got {props2.get('Value')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
