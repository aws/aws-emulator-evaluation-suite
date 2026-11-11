"""list-resources-properties-match-get-resource."""
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

def _list_resources(cc, type_name, **kwargs):
    return cc.list_resources(TypeName=type_name, **kwargs)

def _ssm_desired_state(name, value="v1", ptype="String"):
    return json.dumps({"Name": name, "Type": ptype, "Value": value})

CHECK = "list-resources-properties-match-get-resource"
GROUP = 'lifecycle'
SERVICES = ['cloudcontrol']
SSM_PARAM_TYPE = "AWS::SSM::Parameter"

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListResources and GetResource present a consistent (non-divergent) view of the same resource: the identifier agrees, and every property key present in BOTH payloads carries the same value. ListResources may legitimately return only a summary projection, so absent keys are allowed -- contradictory keys are not."""
    cc = ctx.client("cloudcontrol")
    name = ctx.unique_name("sim2real-behav-cc-param-")
    event = _create_and_wait(cc, ctx, SSM_PARAM_TYPE, _ssm_desired_state(name, value="list-consistency"))
    assert event["OperationStatus"] == "SUCCESS", f"create did not succeed: {event}"

    def find_in_list():
        resp = _list_resources(cc, SSM_PARAM_TYPE)
        for d in resp.get("ResourceDescriptions", []):
            if d["Identifier"] == name:
                return d
        return None

    listed = _poll_until(find_in_list, lambda d: d is not None, timeout_s=60, interval_s=2)
    assert listed["Identifier"] == name, f"ListResources returned the wrong identifier: {listed}"
    list_props = json.loads(listed.get("Properties") or "{}")

    get_resp = _get_resource(cc, SSM_PARAM_TYPE, name)
    assert get_resp["ResourceDescription"]["Identifier"] == name, (
        f"GetResource returned the wrong identifier: {get_resp['ResourceDescription']}"
    )
    get_props = json.loads(get_resp["ResourceDescription"]["Properties"])

    # GetResource is the authoritative read: it must reflect what we created.
    assert get_props.get("Name") == name, f"GetResource identifier property mismatch: {get_props}"
    assert get_props.get("Value") == "list-consistency", (
        f"GetResource did not reflect the created value: {get_props}"
    )

    # ListResources's projection must not invent a property GetResource does not have at all --
    # confirmed against real AWS: for AWS::SSM::Parameter, ListResources' Properties is only
    # ever {"Name": <identifier>} (a strict, identifier-only summary), so this is never vacuous
    # in the direction that matters -- a target that pads the ListResources projection with a
    # key absent from the authoritative GetResource read is itself a divergence.
    extra_keys = set(list_props) - set(get_props)
    assert not extra_keys, (
        f"ListResources exposed propert{'y' if len(extra_keys) == 1 else 'ies'} "
        f"{sorted(extra_keys)!r} that GetResource does not have at all: "
        f"list={list_props!r} get={get_props!r}"
    )

    # ListResources must not contradict GetResource on any shared key.
    shared_keys = set(list_props) & set(get_props)
    for key in sorted(shared_keys):
        assert list_props[key] == get_props[key], (
            f"ListResources and GetResource disagree on {key!r}: "
            f"{list_props[key]!r} vs {get_props[key]!r}"
        )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
