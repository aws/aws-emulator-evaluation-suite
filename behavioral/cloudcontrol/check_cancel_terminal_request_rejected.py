"""cancel-terminal-request-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-terminal-request-rejected"
GROUP = "ordering"
SERVICES = ["cloudcontrol"]

_TERMINAL = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
_PARAM_TYPE = "AWS::SSM::Parameter"
_TABLE_TYPE = "AWS::DynamoDB::Table"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelResourceRequest on a request already at SUCCESS is rejected with ValidationException
    and leaves the resource untouched; only PENDING/IN_PROGRESS requests are cancelable, so a
    cancel issued while a request is in flight succeeds."""
    cc = ctx.client("cloudcontrol")

    # --- break exactly one thing: cancel a request that is already terminal ---
    param_name = ctx.unique_name("sim2real-behav-ccapi-term-")
    ctx.on_cleanup(lambda: _best_effort_delete(cc, _PARAM_TYPE, param_name))

    create_event = cc.create_resource(
        TypeName=_PARAM_TYPE,
        DesiredState=json.dumps(
            {"Name": param_name, "Type": "String", "Value": "v1", "Tags": {"sim2real": CHECK}}
        ),
    )["ProgressEvent"]
    final = _poll_request_terminal(cc, create_event["RequestToken"])
    assert final["OperationStatus"] == "SUCCESS", final

    cancel_code, cancel_message = _client_error(
        lambda: cc.cancel_resource_request(RequestToken=create_event["RequestToken"])
    )
    assert cancel_code == "ValidationException", cancel_code
    expected = f"Request {create_event['RequestToken']} is already in status SUCCESS"
    assert cancel_message == expected, f"expected message {expected!r}, got {cancel_message!r}"

    # effect absent: the already-completed create was not rolled back, and the
    # request's own status is unaffected by the rejected cancel attempt
    restatus = cc.get_resource_request_status(RequestToken=create_event["RequestToken"])["ProgressEvent"]
    assert restatus["OperationStatus"] == "SUCCESS", restatus
    got = cc.get_resource(TypeName=_PARAM_TYPE, Identifier=param_name)
    assert got["ResourceDescription"]["Identifier"] == param_name, (
        f"resource disappeared after a rejected cancel: {got}"
    )

    # --- positive control: cancel a request that is genuinely still in flight ---
    # DynamoDB table creation takes long enough to stabilize that a cancel issued
    # immediately after CreateResource returns is reliably still PENDING/IN_PROGRESS.
    table_name = ctx.unique_name("sim2real-behav-ccapi-inflight-")
    ctx.on_cleanup(lambda: _best_effort_delete(cc, _TABLE_TYPE, table_name))
    table_event = cc.create_resource(
        TypeName=_TABLE_TYPE,
        DesiredState=json.dumps(
            {
                "TableName": table_name,
                "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                "BillingMode": "PAY_PER_REQUEST",
                "Tags": [{"Key": "sim2real", "Value": CHECK}],
            }
        ),
    )["ProgressEvent"]
    try:
        cc.cancel_resource_request(RequestToken=table_event["RequestToken"])
    except ClientError as exc:
        raise AssertionError(
            f"expected the in-flight cancel to succeed, got {exc.response['Error']['Code']}"
        ) from exc
    control_final = _poll_request_terminal(cc, table_event["RequestToken"], timeout_s=180.0)
    assert control_final["OperationStatus"] == "CANCEL_COMPLETE", control_final


def _client_error(fn) -> tuple[str, str]:
    """The (code, message) of the ClientError fn() raises; raises if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _poll_request_terminal(cc: Any, request_token: str, timeout_s: float = 90.0, interval_s: float = 2.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]
        if last.get("OperationStatus") in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {request_token} did not reach a terminal state in {timeout_s}s: {last}")


def _best_effort_delete(cc: Any, type_name: str, identifier: str) -> None:
    """Delete and wait; an already-gone resource is fine, any other outcome raises."""
    try:
        event = cc.delete_resource(TypeName=type_name, Identifier=identifier)["ProgressEvent"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    final = _poll_request_terminal(cc, event["RequestToken"], timeout_s=120.0)
    if final["OperationStatus"] != "SUCCESS" and final.get("ErrorCode") != "NotFound":
        raise AssertionError(f"deleting {identifier} ended {final['OperationStatus']}: {final}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
