"""get-resource-request-status-invalid-token-rejected."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-resource-request-status-invalid-token-rejected"
GROUP = "ordering"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetResourceRequestStatus of an unknown UUID RequestToken is refused with
    RequestTokenNotFoundException and "Request with token <token> was not found", while the token
    of a create this check submitted is echoed back with OperationStatus SUCCESS."""
    cc = ctx.client("cloudcontrol")
    teardown = _Teardown()

    bogus_token = str(uuid.uuid4())
    code, message = _error(lambda: cc.get_resource_request_status(RequestToken=bogus_token))
    assert code == "RequestTokenNotFoundException", (
        f"expected RequestTokenNotFoundException for an unknown token, got {code}"
    )
    expected_message = f"Request with token {bogus_token} was not found"
    assert message == expected_message, (
        f"expected the refusal message {expected_message!r}, got {message!r}"
    )

    # positive control: a freshly submitted, real request token is accepted
    name = ctx.unique_name("sim2real-cc-neg-")
    resp = cc.create_resource(
        TypeName="AWS::SQS::Queue", DesiredState=json.dumps({"QueueName": name})
    )
    token = resp["ProgressEvent"]["RequestToken"]
    final_pe, _ = _wait_for_request(ctx, token)
    ctx.on_cleanup(lambda i=final_pe["Identifier"]: _delete_resource(cc, "AWS::SQS::Queue", i, teardown))

    status_resp = cc.get_resource_request_status(RequestToken=token)
    actual_token = status_resp["ProgressEvent"]["RequestToken"]
    assert actual_token == token, f"expected RequestToken {token!r} echoed back, got {actual_token!r}"
    actual_status = status_resp["ProgressEvent"]["OperationStatus"]
    assert actual_status == "SUCCESS", f"expected the real request to reach SUCCESS, got {actual_status!r}"


def _error(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises, so a
    target that accepts a token AWS refuses fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the bogus token to be rejected, but the call SUCCEEDED and returned {result!r}")


def _wait_for_request(ctx: Any, token: str, timeout_s: float = 150.0, interval_s: float = 2.0):
    cc = ctx.client("cloudcontrol")
    terminal = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
    history: list[str] = []
    deadline = time.monotonic() + timeout_s
    last_pe = None
    while time.monotonic() < deadline:
        resp = cc.get_resource_request_status(RequestToken=token)
        last_pe = resp["ProgressEvent"]
        history.append(last_pe["OperationStatus"])
        if last_pe["OperationStatus"] in terminal:
            return last_pe, history
        time.sleep(interval_s)
    raise AssertionError(f"request {token} did not reach a terminal state within {timeout_s}s (history={history})")


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
