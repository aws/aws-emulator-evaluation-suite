"""request-status-operation-field-reflects-update."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

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

def _create_and_wait(cc, ctx, type_name, desired_state, client_token=None, track=True):
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
            _track(cc, ctx, type_name, identifier)
    return event

def _ssm_desired_state(name, value="v1", ptype="String"):
    return json.dumps({"Name": name, "Type": ptype, "Value": value})

CHECK = "request-status-operation-field-reflects-update"
GROUP = 'lifecycle'
SERVICES = ['cloudcontrol']
SSM_PARAM_TYPE = "AWS::SSM::Parameter"

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResourceRequestStatus reports Operation=UPDATE (not CREATE) for a request issued via UpdateResource."""
    cc = ctx.client("cloudcontrol")
    name = ctx.unique_name("sim2real-behav-cc-param-")
    create_event = _create_and_wait(cc, ctx, SSM_PARAM_TYPE, _ssm_desired_state(name))
    assert create_event["OperationStatus"] == "SUCCESS", f"prerequisite create did not succeed: {create_event}"

    patch = json.dumps([{"op": "replace", "path": "/Value", "value": "updated"}])
    resp = cc.update_resource(TypeName=SSM_PARAM_TYPE, Identifier=name, PatchDocument=patch)
    initial_event = resp["ProgressEvent"]
    token = initial_event["RequestToken"]
    assert initial_event.get("Operation") == "UPDATE", (
        f"UpdateResource's own synchronous response should already report Operation=UPDATE, "
        f"got {initial_event.get('Operation')!r}"
    )

    event = _wait_terminal(cc, token)
    assert event["OperationStatus"] == "SUCCESS", f"update did not reach SUCCESS: {event}"
    assert event["Operation"] == "UPDATE", f"expected UPDATE, got {event.get('Operation')}"

    status_resp = cc.get_resource_request_status(RequestToken=token)
    assert status_resp["ProgressEvent"]["Operation"] == "UPDATE", (
        f"a fresh GetResourceRequestStatus call for token {token} should still report Operation=UPDATE, "
        f"got {status_resp['ProgressEvent'].get('Operation')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
