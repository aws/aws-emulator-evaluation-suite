"""create-resource-success-get."""
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

def _get_resource(cc, type_name, identifier):
    return cc.get_resource(TypeName=type_name, Identifier=identifier)

def _ssm_desired_state(name, value="v1", ptype="String", tags=None):
    state = {"Name": name, "Type": ptype, "Value": value}
    if tags:
        state["Tags"] = tags
    return json.dumps(state)

CHECK = "create-resource-success-get"
GROUP = 'lifecycle'
SERVICES = ['cloudcontrol']
SSM_PARAM_TYPE = "AWS::SSM::Parameter"

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateResource stabilizes to SUCCESS and GetResource returns the created properties."""
    cc = ctx.client("cloudcontrol")
    name = ctx.unique_name("sim2real-behav-cc-param-")
    event = _create_and_wait(
        cc, ctx, SSM_PARAM_TYPE,
        _ssm_desired_state(name, value="hello", tags={"sim2real": CHECK}),
    )
    assert event["OperationStatus"] == "SUCCESS", f"create did not succeed: {event}"
    assert event["Operation"] == "CREATE", f"expected Operation CREATE, got {event['Operation']!r}"
    assert event.get("Identifier") == name, (
        f"expected Identifier {name!r}, got {event.get('Identifier')!r}"
    )

    resp = _get_resource(cc, SSM_PARAM_TYPE, name)
    props = json.loads(resp["ResourceDescription"]["Properties"])
    assert props.get("Name") == name, f"expected Properties.Name {name!r}, got {props.get('Name')!r}"
    assert props.get("Value") == "hello", (
        f"expected Properties.Value 'hello', got {props.get('Value')!r}"
    )
    assert resp["ResourceDescription"]["Identifier"] == name, (
        f"expected ResourceDescription.Identifier {name!r}, got "
        f"{resp['ResourceDescription']['Identifier']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
