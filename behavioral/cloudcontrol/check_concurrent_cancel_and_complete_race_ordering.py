"""concurrent-cancel-and-complete-race-ordering."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-cancel-and-complete-race-ordering"
GROUP = "ordering"
SERVICES = ["cloudcontrol"]

_TERMINAL = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
_TYPE_NAME = "AWS::DynamoDB::Table"


def _desired_state(name: str) -> str:
    # A DynamoDB table takes tens of seconds to stabilize, which gives the immediate cancel a
    # genuine non-terminal window; a type that completes synchronously would always win the race.
    return json.dumps(
        {
            "TableName": name,
            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
            "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
            "BillingMode": "PAY_PER_REQUEST",
            "Tags": [{"Key": "sim2real", "Value": CHECK}],
        }
    )


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelResourceRequest raced against the create's own completion resolves to one stable
    terminal state consistent with the resource: SUCCESS means it exists, CANCEL_COMPLETE means
    it was never created."""
    cc = ctx.client("cloudcontrol")
    name = ctx.unique_name("sim2real-behav-ccapi-race-")
    ctx.on_cleanup(lambda: _best_effort_delete(cc, name))

    create_event = cc.create_resource(
        TypeName=_TYPE_NAME,
        DesiredState=_desired_state(name),
    )["ProgressEvent"]
    request_token = create_event["RequestToken"]

    # Fire the cancel as fast as possible after the create was submitted, to race it
    # against the underlying handler's own completion.
    try:
        cc.cancel_resource_request(RequestToken=request_token)
        cancel_code, cancel_message = None, None
    except ClientError as exc:
        cancel_code, cancel_message = exc.response["Error"]["Code"], exc.response["Error"]["Message"]

    if cancel_code is not None:
        # The operation had already reached a terminal state before the cancel could
        # take effect - only PENDING/IN_PROGRESS requests are cancelable; empirically
        # AWS rejects a too-late cancel with ValidationException.
        assert cancel_code == "ValidationException", (
            f"expected ValidationException for a cancel arriving after the create had "
            f"already reached a terminal state, got {cancel_code!r}"
        )
        expected = f"Request {request_token} is already in status SUCCESS"
        assert cancel_message == expected, f"expected message {expected!r}, got {cancel_message!r}"
        final = cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]
        assert final["OperationStatus"] == "SUCCESS", (
            f"expected the already-terminal request to still read SUCCESS, got {final!r}"
        )
    else:
        final = _poll_request_terminal(cc, request_token, timeout_s=180.0)
        assert final["OperationStatus"] in ("SUCCESS", "CANCEL_COMPLETE"), (
            f"expected the accepted cancel to resolve to SUCCESS or CANCEL_COMPLETE, got {final!r}"
        )
        # The terminal state must be stable: re-reading it must not flap to a
        # different terminal value.
        reread = cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]
        assert reread["OperationStatus"] == final["OperationStatus"], (final, reread)

    # Whichever branch won the race, the request status must be consistent with the
    # actual resource state - never "SUCCESS" with no resource, nor "CANCEL_COMPLETE"
    # with a resource that got created anyway.
    if final["OperationStatus"] == "SUCCESS":
        try:
            cc.get_resource(TypeName=_TYPE_NAME, Identifier=name)
        except ClientError as exc:
            raise AssertionError(
                f"status SUCCESS but GetResource failed with {exc.response['Error']['Code']}"
            ) from exc
    else:
        assert final["OperationStatus"] == "CANCEL_COMPLETE", (
            f"expected the non-SUCCESS terminal state to be CANCEL_COMPLETE, got {final!r}"
        )
        get_code, get_message = _client_error(
            lambda: cc.get_resource(TypeName=_TYPE_NAME, Identifier=name)
        )
        assert get_code == "ResourceNotFoundException", (
            f"status CANCEL_COMPLETE but GetResource returned {get_code!r} (resource may exist)"
        )
        expected_get = _table_not_found(name, get_message)
        assert get_message == expected_get, f"expected message {expected_get!r}, got {get_message!r}"


def _client_error(fn) -> tuple[str, str]:
    """The (code, message) of the ClientError fn() raises; raises if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _table_not_found(table_name, message):
    """The table handler's NotFound text; its RequestToken is minted per call, so it is read back."""
    token = message.rpartition("RequestToken: ")[2].removesuffix(")")
    return (
        f"{_TYPE_NAME} Handler returned status FAILED: Table: {table_name} does not exist. "
        f"(HandlerErrorCode: NotFound, RequestToken: {token})"
    )


def _poll_request_terminal(cc: Any, request_token: str, timeout_s: float = 90.0, interval_s: float = 1.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]
        if last.get("OperationStatus") in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {request_token} did not reach a terminal state in {timeout_s}s: {last}")


def _best_effort_delete(cc: Any, identifier: str) -> None:
    """Delete and wait; an already-gone (or never-created) table is fine, any other outcome raises."""
    try:
        event = cc.delete_resource(TypeName=_TYPE_NAME, Identifier=identifier)["ProgressEvent"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    final = _poll_request_terminal(cc, event["RequestToken"], timeout_s=60.0)
    if final["OperationStatus"] != "SUCCESS" and final.get("ErrorCode") != "NotFound":
        raise AssertionError(f"deleting {identifier} ended {final['OperationStatus']}: {final}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
