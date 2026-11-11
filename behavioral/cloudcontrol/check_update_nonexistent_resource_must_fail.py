"""update-nonexistent-resource-must-fail."""
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

def _error_code(fn):
    """Call fn(); return its ClientError code and message. An unexpected SUCCESS raises, so a target that
    accepts what AWS refuses is never read as a plain code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _handler_not_found(message, detail):
    """The handler's NotFound text; its RequestToken is minted per call, so it is read back."""
    token = message.rpartition("RequestToken: ")[2].removesuffix(")")
    return f"{detail} (HandlerErrorCode: NotFound, RequestToken: {token})"

def _wait_terminal(cc, request_token, timeout_s=90, interval_s=2):
    """Poll GetResourceRequestStatus to a terminal OperationStatus; return the ProgressEvent."""
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

def _delete_parameter_quiet(ssm, name):
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise

def _failure_outcome(cc, call):
    """Invoke a mutating call expected to be refused; return (sync_error, terminal_event)
    with exactly one element non-None."""
    try:
        resp = call()
    except ClientError as exc:
        return exc.response.get("Error", {}), None
    return None, _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"])

def _normalized_failure(cc, call):
    """Exception-style (code, message) for a call expected to fail, whether refused
    synchronously or via a terminal FAILED ProgressEvent."""
    error, event = _failure_outcome(cc, call)
    if error is not None:
        return error.get("Code"), error.get("Message", "")
    status = event.get("OperationStatus")
    assert status == "FAILED", (
        f"operation was expected to be refused but reached {status}: {event}"
    )
    handler_code = event.get("ErrorCode")
    return HANDLER_ERROR_TO_EXCEPTION.get(handler_code, handler_code), event.get("StatusMessage", "")

CHECK = "update-nonexistent-resource-must-fail"
GROUP = 'overly-permissive'
SERVICES = ['cloudcontrol']
SSM_PARAM_TYPE = "AWS::SSM::Parameter"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateResource on a nonexistent SSM parameter is refused with ResourceNotFoundException and
    does not upsert it; the same update on an existing parameter succeeds and takes effect."""
    cc = ctx.client("cloudcontrol")
    ssm = ctx.client("ssm")

    control_name = ctx.unique_name("sim2real-behav-cc-param-ctl-")
    ssm.put_parameter(
        Name=control_name, Value="before", Type="String",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_parameter_quiet(ssm, control_name))
    control_patch = json.dumps([{"op": "replace", "path": "/Value", "value": "after"}])
    control_resp = cc.update_resource(
        TypeName=SSM_PARAM_TYPE, Identifier=control_name, PatchDocument=control_patch
    )
    control_event = _wait_terminal(cc, control_resp["ProgressEvent"]["RequestToken"])
    assert control_event["OperationStatus"] == "SUCCESS", (
        f"positive control: UpdateResource against an existing parameter must succeed, got {control_event!r}"
    )
    control_value = ssm.get_parameter(Name=control_name)["Parameter"]["Value"]
    assert control_value == "after", (
        f"positive control: expected the update to take effect, got Value={control_value!r}"
    )

    name = ctx.unique_name("sim2real-behav-cc-param-")
    patch = json.dumps([{"op": "replace", "path": "/Value", "value": "upserted"}])
    # The message ends in the server-chosen RequestToken of the handler invocation, which no
    # response returns, so its stable prefix and suffix are graded.
    code, message = _normalized_failure(cc,
        lambda: cc.update_resource(
            TypeName=SSM_PARAM_TYPE, Identifier=name, PatchDocument=patch
        )
    )
    assert code == "ResourceNotFoundException", (
        f"update of a nonexistent resource must be refused, got {code}"
    )
    expected = _handler_not_found(
        message,
        f"{SSM_PARAM_TYPE} Handler returned status FAILED: Resource of type '{SSM_PARAM_TYPE}' "
        f"with identifier '{name}' was not found.",
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    not_found, not_found_message = _error_code(lambda: _get_resource(cc, SSM_PARAM_TYPE, name))
    assert not_found == "ResourceNotFoundException", (
        f"a refused update must not upsert the resource, got {not_found}"
    )
    expected = _handler_not_found(
        not_found_message,
        f"{SSM_PARAM_TYPE} Handler returned status FAILED: Resource of type '{SSM_PARAM_TYPE}' "
        f"with identifier '{name}' was not found.",
    )
    assert not_found_message == expected, f"expected message {expected!r}, got {not_found_message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
