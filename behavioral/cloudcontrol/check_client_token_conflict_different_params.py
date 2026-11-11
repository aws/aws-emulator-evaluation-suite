"""client-token-conflict-different-params."""
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
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _handler_not_found(type_name, identifier, message):
    """The handler's NotFound text; its RequestToken is minted per call, so it is read back."""
    token = message.rpartition("RequestToken: ")[2].removesuffix(")")
    return (
        f"{type_name} Handler returned status FAILED: Resource of type '{type_name}' with "
        f"identifier '{identifier}' was not found. (HandlerErrorCode: NotFound, RequestToken: {token})"
    )

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

def _get_resource(cc, type_name, identifier):
    return cc.get_resource(TypeName=type_name, Identifier=identifier)

def _ssm_desired_state(name, value="v1", ptype="String"):
    return json.dumps({
        "Name": name, "Type": ptype, "Value": value,
        "Tags": {"sim2real": CHECK},
    })

CHECK = "client-token-conflict-different-params"
GROUP = 'overly-permissive'
SERVICES = ['cloudcontrol']
SSM_PARAM_TYPE = "AWS::SSM::Parameter"

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """[overly-permissive] Reusing a ClientToken for a materially different CreateResource request must fail with ClientTokenConflictException, not proceed with the new (different) request."""
    cc = ctx.client("cloudcontrol")
    shared_token = ctx.unique_name("sim2real-behav-client-token-")
    name_a = ctx.unique_name("sim2real-behav-cc-param-")
    name_b = ctx.unique_name("sim2real-behav-cc-param-")

    resp_a = cc.create_resource(
        TypeName=SSM_PARAM_TYPE, DesiredState=_ssm_desired_state(name_a), ClientToken=shared_token
    )
    token_a = resp_a["ProgressEvent"]["RequestToken"]
    event_a = _wait_terminal(cc, token_a)
    assert event_a.get("OperationStatus") == "SUCCESS", (
        f"positive control: CreateResource for {name_a!r} must succeed, got {event_a!r}"
    )
    _track(cc, ctx, SSM_PARAM_TYPE, name_a)

    code, message = _client_error(
        lambda: cc.create_resource(
            TypeName=SSM_PARAM_TYPE, DesiredState=_ssm_desired_state(name_b), ClientToken=shared_token
        )
    )
    assert code == "ClientTokenConflictException", (
        f"reusing a ClientToken for a different request must fail, got {code}"
    )
    expected = (
        f"ClientToken {shared_token} is already associated with an existing operation with "
        f"RequestToken {token_a}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # the conflicting (never-accepted) resource must not exist
    not_found_code, not_found_message = _client_error(lambda: _get_resource(cc, SSM_PARAM_TYPE, name_b))
    assert not_found_code == "ResourceNotFoundException", (
        f"the never-accepted resource {name_b!r} must read back as ResourceNotFoundException, "
        f"got {not_found_code!r}"
    )
    expected_nf = _handler_not_found(SSM_PARAM_TYPE, name_b, not_found_message)
    assert not_found_message == expected_nf, (
        f"expected message {expected_nf!r}, got {not_found_message!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
