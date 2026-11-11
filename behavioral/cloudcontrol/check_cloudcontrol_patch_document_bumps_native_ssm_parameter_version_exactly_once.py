"""cloudcontrol-patch-document-bumps-native-ssm-parameter-version-exactly-once."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cloudcontrol-patch-document-bumps-native-ssm-parameter-version-exactly-once"
GROUP = 'native-truth'
SERVICES = ['cloudcontrol']
SSM_PARAM_TYPE = "AWS::SSM::Parameter"
TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}


def _poll_until(probe, predicate, *, timeout_s=120, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _wait_terminal(cc, request_token, *, timeout_s=120, interval_s=2.0):
    """Poll GetResourceRequestStatus to a terminal OperationStatus; return the ProgressEvent."""
    return _poll_until(
        lambda: cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"],
        lambda e: e is not None and e.get("OperationStatus") in TERMINAL_STATUSES,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"request {request_token} reaching a terminal OperationStatus",
    )


def _delete_parameter_quiet(ssm, name):
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise


def _history(ssm, name):
    out = []
    for page in ssm.get_paginator("get_parameter_history").paginate(Name=name):
        out.extend({"Version": h["Version"], "Value": h["Value"]} for h in page["Parameters"])
    return out


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """One JSON-Patch UpdateResource of /Value advances the SSM parameter Version from 1 to exactly
    2, with a history of exactly two entries whose Version 1 holds v1 and Version 2 holds v2."""
    cc = ctx.client("cloudcontrol")
    ssm = ctx.client("ssm")
    name = ctx.unique_name("sim2real-behav-ccbump-")

    resp = cc.create_resource(
        TypeName=SSM_PARAM_TYPE,
        DesiredState=json.dumps({
            "Name": name, "Type": "String", "Value": "v1", "Tags": {"sim2real": CHECK},
        }),
    )
    ctx.on_cleanup(lambda: _delete_parameter_quiet(ssm, name))
    create_event = _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"])
    assert create_event["OperationStatus"] == "SUCCESS", f"create did not succeed: {create_event!r}"

    patched = cc.update_resource(
        TypeName=SSM_PARAM_TYPE, Identifier=name,
        PatchDocument=json.dumps([{"op": "replace", "path": "/Value", "value": "v2"}]),
    )
    update_event = _wait_terminal(cc, patched["ProgressEvent"]["RequestToken"])
    assert update_event["OperationStatus"] == "SUCCESS", f"update did not succeed: {update_event!r}"
    assert update_event["Operation"] == "UPDATE", (
        f"the patch was recorded as Operation {update_event['Operation']!r}, expected 'UPDATE'"
    )

    after = ssm.get_parameter(Name=name)["Parameter"]
    assert after["Value"] == "v2", f"SSM holds Value {after['Value']!r}, expected 'v2'"
    assert after["Version"] == 2, (
        f"SSM reports Version {after['Version']!r}; one patch of /Value must advance the native "
        "counter from 1 to exactly 2"
    )

    # GetParameterHistory documents no result order, so entries are sorted by their Version.
    history = sorted(_history(ssm, name), key=lambda h: h["Version"])
    assert [h["Version"] for h in history] == [1, 2], (
        f"SSM parameter history versions are {[h['Version'] for h in history]!r}, expected [1, 2]"
    )
    assert [h["Value"] for h in history] == ["v1", "v2"], (
        f"SSM parameter history values are {[h['Value'] for h in history]!r}, expected "
        "['v1', 'v2'] for Versions [1, 2]"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
