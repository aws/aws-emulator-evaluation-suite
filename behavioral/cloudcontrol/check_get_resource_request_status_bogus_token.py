"""get-resource-request-status-bogus-token."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")

def _wait_terminal(cc, token, timeout_s=150.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    history = []
    while time.monotonic() < deadline:
        last = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
        history.append(last["OperationStatus"])
        if last["OperationStatus"] in ("SUCCESS", "FAILED", "CANCEL_COMPLETE"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {token} did not reach a terminal state within {timeout_s}s (history={history})")

CHECK = "get-resource-request-status-bogus-token"
GROUP = 'error-semantics'
SERVICES = ['cloudcontrol']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetResourceRequestStatus of a never-issued RequestToken is refused with
    RequestTokenNotFoundException and "Request with token <token> was not found", while the same
    call for the token of a create this check submitted returns that request as SUCCESS."""
    cc = ctx.client("cloudcontrol")
    teardown = _Teardown()

    name = ctx.unique_name("sim2real-cc-bogus-token-")
    desired_state = json.dumps({"QueueName": name, "Tags": [{"Key": "sim2real", "Value": CHECK}]})
    progress = cc.create_resource(TypeName="AWS::SQS::Queue", DesiredState=desired_state)["ProgressEvent"]
    real_token = progress["RequestToken"]
    final = _wait_terminal(cc, real_token)
    assert final["OperationStatus"] == "SUCCESS", f"queue create failed: {final}"
    ctx.on_cleanup(lambda: _delete_resource(cc, "AWS::SQS::Queue", final["Identifier"], teardown))

    control = cc.get_resource_request_status(RequestToken=real_token)["ProgressEvent"]
    assert control["RequestToken"] == real_token, f"expected {real_token}, got {control['RequestToken']}"
    assert control["OperationStatus"] == "SUCCESS", f"expected SUCCESS for the real token, got {control}"

    bogus_token = ctx.unique_name("sim2real-behav-bogus-request-token-") + "-0000-0000-0000-000000000000"
    code, message = _error(lambda: cc.get_resource_request_status(RequestToken=bogus_token))
    assert code == "RequestTokenNotFoundException", f"expected RequestTokenNotFoundException, got {code}"
    assert message == f"Request with token {bogus_token} was not found", (
        f"the refusal must name the unknown token, got {message!r}"
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
