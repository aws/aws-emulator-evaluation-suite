"""update-resource-updates-value."""
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
    """Teardown: an identifier already gone is fine; a delete that never terminates raises."""
    try:
        resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"], timeout_s=60, interval_s=2)

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

def _update_and_wait(cc, type_name, identifier, patch_document, client_token=None):
    kwargs = {"TypeName": type_name, "Identifier": identifier, "PatchDocument": patch_document}
    if client_token:
        kwargs["ClientToken"] = client_token
    resp = cc.update_resource(**kwargs)
    return _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"])

def _get_resource(cc, type_name, identifier):
    return cc.get_resource(TypeName=type_name, Identifier=identifier)

def _ssm_desired_state(name, value="v1", ptype="String", resource_tags=None):
    state = {"Name": name, "Type": ptype, "Value": value}
    if resource_tags:
        state["Tags"] = resource_tags
    return json.dumps(state)

CHECK = "update-resource-updates-value"
GROUP = 'lifecycle'
SERVICES = ['cloudcontrol']
SSM_PARAM_TYPE = "AWS::SSM::Parameter"

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateResource applies a JSON Patch and the new value is visible via GetResource after stabilization."""
    cc = ctx.client("cloudcontrol")
    name = ctx.unique_name("sim2real-behav-cc-param-")
    create_event = _create_and_wait(
        cc, ctx, SSM_PARAM_TYPE,
        _ssm_desired_state(name, value="before", resource_tags={"sim2real": CHECK}),
    )
    assert create_event["OperationStatus"] == "SUCCESS", f"create did not succeed: {create_event}"

    patch = json.dumps([{"op": "replace", "path": "/Value", "value": "after"}])
    update_event = _update_and_wait(cc, SSM_PARAM_TYPE, name, patch)
    assert update_event["OperationStatus"] == "SUCCESS", f"update did not succeed: {update_event}"
    assert update_event["Operation"] == "UPDATE", (
        f"expected Operation 'UPDATE', got {update_event.get('Operation')!r}: {update_event}"
    )

    resp = _get_resource(cc, SSM_PARAM_TYPE, name)
    props = json.loads(resp["ResourceDescription"]["Properties"])
    assert props.get("Value") == "after", f"update not reflected: {props}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
