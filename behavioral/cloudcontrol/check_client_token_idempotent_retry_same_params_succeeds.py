"""client-token-idempotent-retry-same-params-succeeds."""
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
    """Delete and wait; an already-gone resource is fine, any other outcome raises."""
    try:
        resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    final = _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"], timeout_s=60, interval_s=2)
    if final["OperationStatus"] != "SUCCESS" and final.get("ErrorCode") != "NotFound":
        raise AssertionError(f"deleting {identifier} ended {final['OperationStatus']}: {final}")

def _track(cc, ctx, type_name, identifier):
    ctx.on_cleanup(lambda: _delete_quiet(cc, type_name, identifier))

def _ssm_desired_state(name, value="v1", ptype="String"):
    return json.dumps({"Name": name, "Type": ptype, "Value": value})

CHECK = "client-token-idempotent-retry-same-params-succeeds"
GROUP = 'lifecycle'
SERVICES = ['cloudcontrol']
SSM_PARAM_TYPE = "AWS::SSM::Parameter"

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Retrying CreateResource with the same ClientToken and DesiredState succeeds with the same
    identifier, and SSM shows the parameter was written once (Version 1, one history entry)."""
    cc = ctx.client("cloudcontrol")
    ssm = ctx.client("ssm")
    shared_token = ctx.unique_name("sim2real-behav-client-token-")
    name = ctx.unique_name("sim2real-behav-cc-param-")
    desired_state = _ssm_desired_state(name, value="idempotent")

    resp_a = cc.create_resource(TypeName=SSM_PARAM_TYPE, DesiredState=desired_state, ClientToken=shared_token)
    token_a = resp_a["ProgressEvent"]["RequestToken"]
    event_a = _wait_terminal(cc, token_a)
    assert event_a["OperationStatus"] == "SUCCESS", f"initial create must succeed: {event_a!r}"
    _track(cc, ctx, SSM_PARAM_TYPE, name)

    resp_b = cc.create_resource(TypeName=SSM_PARAM_TYPE, DesiredState=desired_state, ClientToken=shared_token)
    token_b = resp_b["ProgressEvent"]["RequestToken"]
    event_b = _wait_terminal(cc, token_b)
    assert event_b["OperationStatus"] == "SUCCESS", f"idempotent retry must not fail: {event_b}"
    assert event_b.get("Identifier") == name, (
        f"idempotent retry resolved to identifier {event_b.get('Identifier')!r}, expected {name!r}"
    )

    param = ssm.get_parameter(Name=name, WithDecryption=False)["Parameter"]
    assert param["Version"] == 1, (
        f"SSM reports Version {param['Version']!r} after a same-token, same-params retry; an "
        "idempotent retry must not write the native parameter a second time"
    )
    history = [
        h["Version"]
        for page in ssm.get_paginator("get_parameter_history").paginate(Name=name)
        for h in page["Parameters"]
    ]
    assert history == [1], (
        f"SSM parameter history is {history!r} after the idempotent retry; exactly one write "
        "(Version 1) must exist"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
