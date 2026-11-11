"""progress-event-request-tokens-distinct-and-records-retained."""
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


def _get_resource(cc, type_name, identifier):
    return cc.get_resource(TypeName=type_name, Identifier=identifier)


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message", "")
    raise AssertionError("expected a ClientError, the call unexpectedly succeeded")


#: A RequestToken: a lowercase UUID.
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


def _handler_not_found(message, detail):
    """The handler's NotFound text; its RequestToken (a UUID) is minted per call, so it is read back."""
    token = message.rpartition("RequestToken: ")[2].removesuffix(")")
    token = token if re.fullmatch(_UUID, token) else "<a UUID>"
    return f"{detail} (HandlerErrorCode: NotFound, RequestToken: {token})"


def _ssm_desired_state(name, value="v1", ptype="String", **extra):
    """DesiredState is a JSON *string*, so it is built with json.dumps -- never a YAML library."""
    state = {"Name": name, "Type": ptype, "Value": value}
    state.update(extra)
    return json.dumps(state)


CHECK = "progress-event-request-tokens-distinct-and-records-retained"
GROUP = 'lifecycle'
SERVICES = ['cloudcontrol']
SSM_PARAM_TYPE = "AWS::SSM::Parameter"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Create, update and delete each mint a distinct RequestToken, and after the resource is gone
    every token still resolves to its own operation's SUCCESS ProgressEvent.
    """
    cc = ctx.client("cloudcontrol")
    teardown = _Teardown()
    name = ctx.unique_name("sim2real-behav-cc-param-")

    create_resp = cc.create_resource(
        TypeName=SSM_PARAM_TYPE,
        DesiredState=_ssm_desired_state(name, value="v1", Tags={"sim2real": CHECK}),
    )
    create_token = create_resp["ProgressEvent"]["RequestToken"]
    _track(cc, ctx, SSM_PARAM_TYPE, name, teardown=teardown)
    create_final = _wait_terminal(cc, create_token)
    assert create_final["OperationStatus"] == "SUCCESS", (
        f"create must reach SUCCESS, got {create_final}"
    )

    update_resp = cc.update_resource(
        TypeName=SSM_PARAM_TYPE,
        Identifier=name,
        PatchDocument=json.dumps([{"op": "replace", "path": "/Value", "value": "v2"}]),
    )
    update_token = update_resp["ProgressEvent"]["RequestToken"]
    update_final = _wait_terminal(cc, update_token)
    assert update_final["OperationStatus"] == "SUCCESS", (
        f"update must reach SUCCESS, got {update_final}"
    )

    delete_resp = cc.delete_resource(TypeName=SSM_PARAM_TYPE, Identifier=name)
    delete_token = delete_resp["ProgressEvent"]["RequestToken"]
    delete_final = _wait_terminal(cc, delete_token)
    assert delete_final["OperationStatus"] == "SUCCESS", (
        f"delete must reach SUCCESS, got {delete_final}"
    )

    tokens = [create_token, update_token, delete_token]
    assert len(set(tokens)) == 3, (
        f"each mutating call must mint a distinct RequestToken, got {tokens}"
    )

    # GetResourceRequestStatus is keyed by RequestToken, not by resource: re-read all three AFTER
    # the last operation, so each token must still map to its own operation.
    for token, expected_operation in zip(tokens, ["CREATE", "UPDATE", "DELETE"]):
        event = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
        assert event["RequestToken"] == token, event
        assert event["Operation"] == expected_operation, (
            f"token {token} must still report Operation={expected_operation}, "
            f"got {event.get('Operation')} -- request records are being overwritten"
        )
        assert event["OperationStatus"] == "SUCCESS", event
        assert event["TypeName"] == SSM_PARAM_TYPE, event
        assert event["Identifier"] == name, event

    # the resource really is gone, so the retained records above are records and not live state
    absent, absent_message = _error_code(lambda: _get_resource(cc, SSM_PARAM_TYPE, name))
    assert absent == "ResourceNotFoundException", (
        f"the resource must be deleted while its request records survive, got {absent}"
    )
    expected = _handler_not_found(
        absent_message,
        f"{SSM_PARAM_TYPE} Handler returned status FAILED: Resource of type '{SSM_PARAM_TYPE}' "
        f"with identifier '{name}' was not found.",
    )
    assert absent_message == expected, f"expected message {expected!r}, got {absent_message!r}"


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
