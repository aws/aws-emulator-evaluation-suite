"""create-resource-invalid-type-name."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}


def _error(fn):
    """Call fn(); return the botocore error (Code, Message). An unexpected success raises, so a
    target that wrongly accepts the bogus input fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_terminal(cc, request_token, timeout_s=90.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]
        if last.get("OperationStatus") in TERMINAL_STATUSES:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request never reached a terminal state: {last}")


CHECK = "create-resource-invalid-type-name"
GROUP = 'error-semantics'
SERVICES = ['cloudcontrol']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateResource and ListResources for an unregistered TypeName fail synchronously with
    TypeNotFoundException and exact messages, while the same CreateResource shape for
    AWS::SSM::Parameter succeeds."""
    cc = ctx.client("cloudcontrol")
    bogus_type = "AWS::NoSuch::Service" + ctx.unique_name("sim2real-behav-Type").replace("-", "")

    code, message = _error(
        lambda: cc.create_resource(
            TypeName=bogus_type, DesiredState=json.dumps({"Name": "whatever"})
        )
    )
    assert code == "TypeNotFoundException", f"expected TypeNotFoundException, got {code}"
    expected_message = f"The type '{bogus_type}' cannot be found."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the rejection above was synchronous (no RequestToken/ProgressEvent was ever
    # minted for an unregistered type), so there is nothing to poll. Reinforce via an independent
    # operation, at the same destination, that no resource of this bogus type is ever observable.
    list_code, list_message = _error(lambda: cc.list_resources(TypeName=bogus_type))
    assert list_code == "TypeNotFoundException", (
        f"expected TypeNotFoundException on the independent read, got {list_code}"
    )
    expected_list_message = f"The type '{bogus_type}' cannot be found."
    assert list_message == expected_list_message, (
        f"expected message {expected_list_message!r}, got {list_message!r}"
    )

    # positive control: identical CreateResource shape against a real, registered type succeeds,
    # so the rejection above cannot be mistaken for CreateResource rejecting everything.
    param_name = ctx.unique_name("sim2real-behav-cc-invtype-ctrl-")
    control_resp = cc.create_resource(
        TypeName="AWS::SSM::Parameter",
        DesiredState=json.dumps(
            {"Name": param_name, "Type": "String", "Value": "v1", "Tags": {"sim2real": CHECK}}
        ),
    )
    control_token = control_resp["ProgressEvent"]["RequestToken"]
    teardown = _Teardown()
    ctx.on_cleanup(lambda: _cleanup_request(cc, "AWS::SSM::Parameter", control_token, teardown))
    final = _wait_terminal(cc, control_token)
    assert final["OperationStatus"] == "SUCCESS", f"control create failed: {final}"


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
