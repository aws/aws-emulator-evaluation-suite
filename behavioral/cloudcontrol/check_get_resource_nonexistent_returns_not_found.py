"""get-resource-nonexistent-returns-not-found."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}

def _poll_until(probe, predicate, *, timeout_s=90, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

def _error_code(fn):
    """The error code fn() is refused with. An unexpected SUCCESS raises, so a target that
    serves what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message", "")
    raise AssertionError(f"expected a refusal, but the call SUCCEEDED and returned {result!r}")


#: A RequestToken: a lowercase UUID.
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


def _handler_not_found(message, detail):
    """The handler's NotFound text; its RequestToken (a UUID) is minted per call, so it is read back."""
    token = message.rpartition("RequestToken: ")[2].removesuffix(")")
    token = token if re.fullmatch(_UUID, token) else "<a UUID>"
    return f"{detail} (HandlerErrorCode: NotFound, RequestToken: {token})"

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
        description="CreateResource terminal status",
    )
    return holder["event"]

def _create_and_wait(cc, ctx, type_name, desired_state, *, teardown):
    """CreateResource, wait for a terminal state, and track the identifier for cleanup
    on success. Returns the final ProgressEvent."""
    resp = cc.create_resource(TypeName=type_name, DesiredState=desired_state)
    event = _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"])
    identifier = event.get("Identifier")
    if event.get("OperationStatus") == "SUCCESS" and identifier:
        ctx.on_cleanup(lambda: _delete_resource(cc, type_name, identifier, teardown))
    return event

def _get_resource(cc, type_name, identifier):
    return cc.get_resource(TypeName=type_name, Identifier=identifier)

def _ssm_desired_state(name, value="v1", ptype="String"):
    return json.dumps({"Name": name, "Type": ptype, "Value": value})

CHECK = "get-resource-nonexistent-returns-not-found"
GROUP = 'error-semantics'
SERVICES = ['cloudcontrol']
SSM_PARAM_TYPE = "AWS::SSM::Parameter"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetResource of a never-created SSM parameter is refused with ResourceNotFoundException and the
    handler's not-found message, while GetResource of a parameter just created describes it, so a
    GetResource that fails for every identifier cannot pass."""
    cc = ctx.client("cloudcontrol")
    teardown = _Teardown()

    live_name = ctx.unique_name("sim2real-behav-cc-param-live-")
    create_event = _create_and_wait(cc, ctx, SSM_PARAM_TYPE, _ssm_desired_state(live_name), teardown=teardown)
    assert create_event["OperationStatus"] == "SUCCESS", f"positive control create failed: {create_event}"

    control = _get_resource(cc, SSM_PARAM_TYPE, live_name)
    control_id = control["ResourceDescription"]["Identifier"]
    assert control_id == live_name, f"expected positive control to describe {live_name!r}, got {control_id!r}"

    absent_name = ctx.unique_name("sim2real-behav-cc-param-absent-")
    code, code_message = _error_code(lambda: _get_resource(cc, SSM_PARAM_TYPE, absent_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = _handler_not_found(
        code_message,
        f"{SSM_PARAM_TYPE} Handler returned status FAILED: Resource of type '{SSM_PARAM_TYPE}' "
        f"with identifier '{absent_name}' was not found.",
    )
    assert code_message == expected, f"expected message {expected!r}, got {code_message!r}"


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
