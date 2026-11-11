"""delete-resource-then-not-found."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

def _error(fn):
    """Call fn(); return its ClientError (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


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

def _delete_and_wait(cc, type_name, identifier, client_token=None):
    kwargs = {"TypeName": type_name, "Identifier": identifier}
    if client_token:
        kwargs["ClientToken"] = client_token
    resp = cc.delete_resource(**kwargs)
    return _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"])

def _get_resource(cc, type_name, identifier):
    return cc.get_resource(TypeName=type_name, Identifier=identifier)

def _ssm_desired_state(name, value="v1", ptype="String"):
    return json.dumps({"Name": name, "Type": ptype, "Value": value, "Tags": {"sim2real": CHECK}})

CHECK = "delete-resource-then-not-found"
GROUP = 'lifecycle'
SERVICES = ['cloudcontrol']
SSM_PARAM_TYPE = "AWS::SSM::Parameter"

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteResource stabilizes to SUCCESS and a subsequent GetResource raises ResourceNotFoundException."""
    cc = ctx.client("cloudcontrol")
    teardown = _Teardown()
    name = ctx.unique_name("sim2real-behav-cc-param-")
    create_event = _create_and_wait(cc, ctx, SSM_PARAM_TYPE, _ssm_desired_state(name), teardown=teardown)
    assert create_event["OperationStatus"] == "SUCCESS", f"create did not succeed: {create_event}"

    # Positive control: GetResource must succeed and report this identifier while the
    # resource still exists, so the not-found assertion below cannot be satisfied by a
    # GetResource that is simply broken for every identifier.
    before = _get_resource(cc, SSM_PARAM_TYPE, name)
    assert before["ResourceDescription"]["Identifier"] == name, (
        f"expected GetResource to report identifier {name!r} while the resource exists, "
        f"got {before['ResourceDescription'].get('Identifier')!r}"
    )

    delete_event = _delete_and_wait(cc, SSM_PARAM_TYPE, name)
    assert delete_event["OperationStatus"] == "SUCCESS", f"delete did not succeed: {delete_event}"
    assert delete_event["Operation"] == "DELETE", f"expected Operation DELETE, got {delete_event['Operation']!r}"

    code, message = _error(lambda: _get_resource(cc, SSM_PARAM_TYPE, name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = _handler_not_found(
        message,
        f"{SSM_PARAM_TYPE} Handler returned status FAILED: Resource of type '{SSM_PARAM_TYPE}' "
        f"with identifier '{name}' was not found.",
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


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
