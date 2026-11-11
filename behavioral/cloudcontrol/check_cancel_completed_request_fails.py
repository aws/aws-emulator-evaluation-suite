"""cancel-completed-request-fails."""
from __future__ import annotations

import json
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

def _client_error(fn):
    """The (code, message) of the ClientError fn() raises; raises if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")

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

def _delete_quiet(cc, type_name, identifier):
    try:
        resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
        _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"], timeout_s=60, interval_s=2)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "RequestTokenNotFoundException",
            "ResourceNotFoundException",
            "TypeNotFoundException",
        ):
            raise

def _track(cc, ctx, type_name, identifier):
    ctx.on_cleanup(lambda: _delete_quiet(cc, type_name, identifier))

def _ssm_desired_state(name, value="v1", ptype="String"):
    return json.dumps({"Name": name, "Type": ptype, "Value": value})

CHECK = "cancel-completed-request-fails"
GROUP = 'overly-permissive'
SERVICES = ['cloudcontrol']
SSM_PARAM_TYPE = "AWS::SSM::Parameter"
DDB_TABLE_TYPE = "AWS::DynamoDB::Table"

def _ddb_desired_state(name):
    return json.dumps({
        "TableName": name,
        "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
        "BillingMode": "PAY_PER_REQUEST",
    })

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """[overly-permissive] CancelResourceRequest on a request that already reached a terminal state (SUCCESS) must fail with ValidationException, not silently accept the cancel -- while a same-shaped cancel issued while a request is genuinely still in flight must succeed (positive control, same file)."""
    cc = ctx.client("cloudcontrol")
    name = ctx.unique_name("sim2real-behav-cc-param-")
    resp = cc.create_resource(TypeName=SSM_PARAM_TYPE, DesiredState=_ssm_desired_state(name))
    token = resp["ProgressEvent"]["RequestToken"]
    event = _wait_terminal(cc, token)
    assert event["OperationStatus"] == "SUCCESS"
    _track(cc, ctx, SSM_PARAM_TYPE, name)

    code, message = _client_error(lambda: cc.cancel_resource_request(RequestToken=token))
    # Empirically real AWS refuses this with ValidationException ("cannot be
    # cancelled" because the request already reached a terminal state) rather
    # than the modeled ConcurrentModificationException. The important
    # behavioral property is that the cancel is REFUSED, not silently accepted.
    assert code == "ValidationException", (
        f"cancel of an already-terminal request must fail, got {code}"
    )
    expected = f"Request {token} is already in status SUCCESS"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # request must still report SUCCESS, not have been flipped to a cancel state
    status_resp = cc.get_resource_request_status(RequestToken=token)
    assert status_resp["ProgressEvent"]["OperationStatus"] == "SUCCESS"

    # --- positive control: a same-shaped cancel on a request that is genuinely
    # still in flight must succeed. Without this, "rejects cancel of a completed
    # request" is indistinguishable from "CancelResourceRequest rejects every
    # request" -- a DynamoDB table takes tens of seconds to stabilize, so it is
    # reliably still PENDING/IN_PROGRESS immediately after CreateResource returns.
    table_name = ctx.unique_name("sim2real-behav-cc-table-")
    table_resp = cc.create_resource(TypeName=DDB_TABLE_TYPE, DesiredState=_ddb_desired_state(table_name))
    table_token = table_resp["ProgressEvent"]["RequestToken"]
    _track(cc, ctx, DDB_TABLE_TYPE, table_name)

    try:
        cc.cancel_resource_request(RequestToken=table_token)
    except ClientError as exc:
        raise AssertionError(
            f"expected the in-flight cancel to succeed, got {exc.response['Error']['Code']}"
        ) from exc
    control_final = _wait_terminal(cc, table_token, timeout_s=180, interval_s=3)
    assert control_final["OperationStatus"] in ("CANCEL_COMPLETE", "SUCCESS"), control_final

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
