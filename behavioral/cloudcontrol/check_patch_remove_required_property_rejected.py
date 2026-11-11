"""patch-remove-required-property-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# _refusal returns the failure code and the diagnostic: Cloud Control reports every
# DesiredState/PatchDocument schema violation under one code, so the message is the detail.

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
    """Poll GetResourceRequestStatus until the request reaches a terminal OperationStatus."""
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
        description="request reaches a terminal OperationStatus",
    )
    return holder["event"]


def _track(cc, ctx, type_name, identifier, teardown):
    ctx.on_cleanup(lambda: _delete_resource(cc, type_name, identifier, teardown))


def _create_and_wait(cc, ctx, type_name, desired_state, track=True, *, teardown):
    resp = cc.create_resource(TypeName=type_name, DesiredState=desired_state)
    event = _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"])
    if track and event.get("OperationStatus") == "SUCCESS":
        identifier = event.get("Identifier")
        if identifier:
            _track(cc, ctx, type_name, identifier, teardown)
    return event


def _update_and_wait(cc, type_name, identifier, patch_document):
    resp = cc.update_resource(
        TypeName=type_name, Identifier=identifier, PatchDocument=patch_document
    )
    return _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"])


def _get_resource(cc, type_name, identifier):
    return cc.get_resource(TypeName=type_name, Identifier=identifier)


def _properties(cc, type_name, identifier):
    """GetResource returns Properties as a JSON *string* -- decode it before asserting."""
    resp = _get_resource(cc, type_name, identifier)
    assert resp["ResourceDescription"]["Identifier"] == identifier, resp
    return json.loads(resp["ResourceDescription"]["Properties"])


def _refusal(cc, call):
    """(code, diagnostic) for a mutating call expected to be refused, normalized across the two
    layers Cloud Control can refuse at: synchronously at the front door (ClientError) or
    asynchronously via a terminal FAILED ProgressEvent (ErrorCode + StatusMessage)."""
    try:
        resp = call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    event = _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"])
    status = event.get("OperationStatus")
    assert status == "FAILED", (
        f"operation was expected to be refused but reached {status}: {event}"
    )
    handler_code = event.get("ErrorCode")
    return (
        HANDLER_ERROR_TO_EXCEPTION.get(handler_code, handler_code),
        event.get("StatusMessage") or "",
    )


def _ssm_desired_state(name, value="v1", ptype="String", **extra):
    """DesiredState is a JSON *string*, so it is built with json.dumps -- never a YAML library."""
    state = {"Name": name, "Type": ptype, "Value": value}
    state.update(extra)
    return json.dumps(state)


CHECK = "patch-remove-required-property-rejected"
GROUP = 'error-semantics'
SERVICES = ['cloudcontrol']
SSM_PARAM_TYPE = "AWS::SSM::Parameter"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A JSON Patch "remove" of the required /Value of an SSM parameter is refused with
    ValidationException and the exact required-key diagnostic and leaves Value "keepme", while a
    "replace" of the same property succeeds."""
    cc = ctx.client("cloudcontrol")
    teardown = _Teardown()
    name = ctx.unique_name("sim2real-behav-cc-param-")

    created = _create_and_wait(
        cc, ctx, SSM_PARAM_TYPE,
        _ssm_desired_state(name, value="keepme", Tags={"sim2real": CHECK}), teardown=teardown,
    )
    assert created["OperationStatus"] == "SUCCESS", f"setup create failed: {created}"

    remove_patch = json.dumps([{"op": "remove", "path": "/Value"}])
    code, diagnostic = _refusal(
        cc,
        lambda: cc.update_resource(
            TypeName=SSM_PARAM_TYPE, Identifier=name, PatchDocument=remove_patch
        ),
    )
    # The post-patch state is validated against the schema, which rejects a missing required key.
    assert code == "ValidationException", (
        f"removing a required property must be refused with ValidationException, "
        f"got {code}: {diagnostic}"
    )
    expected_diagnostic = "Model validation failed (#: required key [Value] not found)"
    assert diagnostic == expected_diagnostic, (
        f"expected the required-key refusal {expected_diagnostic!r}, got {diagnostic!r}"
    )

    # effect-absent leg: the property must be present AND unchanged, not merely present.
    props = _properties(cc, SSM_PARAM_TYPE, name)
    assert props.get("Value") == "keepme", (
        f"a refused remove must leave the required property untouched: {props}"
    )

    # control: the same property IS updatable, so the refusal was about removal, not about the
    # property being read-only.
    updated = _update_and_wait(
        cc, SSM_PARAM_TYPE, name,
        json.dumps([{"op": "replace", "path": "/Value", "value": "replaced"}]),
    )
    assert updated["OperationStatus"] == "SUCCESS", f"control patch must succeed: {updated}"
    props = _properties(cc, SSM_PARAM_TYPE, name)
    assert props.get("Value") == "replaced", f"control patch not reflected: {props}"


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
