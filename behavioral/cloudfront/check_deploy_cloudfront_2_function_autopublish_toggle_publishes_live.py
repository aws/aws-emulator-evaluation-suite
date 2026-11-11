"""deploy-cloudfront-2-function-autopublish-toggle-publishes-live."""
from __future__ import annotations

import json
import sys
import time

from behavioral_harness import tags

CHECK = "deploy-cloudfront-2-function-autopublish-toggle-publishes-live"
GROUP = "deploy-cfn-cloudfront-function"
SERVICES = ["cloudfront"]

_CODE = """function handler(event) {
    var request = event.request;
    request.headers['x-deployed-by'] = {value: 'cfn'};
    request.uri = '/published' + request.uri;
    return request;
}
"""

_EVENT = json.dumps({
    "version": "1.0",
    "context": {"eventType": "viewer-request"},
    "viewer": {"ip": "203.0.113.9"},
    "request": {"method": "GET", "uri": "/x", "querystring": {}, "headers": {}, "cookies": {}},
}).encode()


def _template(fn_name: str, auto_publish: bool) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Fn": {
                "Type": "AWS::CloudFront::Function",
                "Properties": {
                    "Name": fn_name,
                    "AutoPublish": auto_publish,
                    "FunctionCode": _CODE,
                    "FunctionConfig": {"Comment": "sim2real autopublish", "Runtime": "cloudfront-js-2.0"},
                },
            },
        },
        "Outputs": {
            "FunctionArn": {"Value": {"Fn::GetAtt": ["Fn", "FunctionARN"]}},
            "Stage": {"Value": {"Fn::GetAtt": ["Fn", "Stage"]}},
        },
    })


@tags("axis:happy-path", "concern:deploy", "plane:control", "cap:c1")
def run(ctx) -> None:
    """A stack-deployed CloudFront Function with AutoPublish false has no LIVE stage; flipping
    AutoPublish to true publishes it in place (same physical id) and LIVE runs the deployed code.
    """
    cfn = ctx.client("cloudformation")
    cf = ctx.client("cloudfront")

    stack = ctx.unique_name("sim2real-cfpub-stack-")
    fn = ctx.unique_name("sim2real-cfpub-fn-")

    cfn.create_stack(StackName=stack, TemplateBody=_template(fn, False),
                     Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_stack_and_verify(ctx, stack, fn))
    _wait_stack_status(cfn, stack, "CREATE_COMPLETE", timeout_s=600)

    out = _outputs(cfn, stack)
    assert out["Stage"] == "DEVELOPMENT", f"AutoPublish:false stack reports Stage {out['Stage']!r}, expected DEVELOPMENT"
    phys_before = _physical_id(cfn, stack, "Fn")
    dev = cf.describe_function(Name=fn, Stage="DEVELOPMENT")["FunctionSummary"]
    assert dev["Status"] == "UNPUBLISHED", (
        f"an AutoPublish:false function reports Status {dev['Status']!r}, expected UNPUBLISHED"
    )
    err = _client_error(lambda: cf.describe_function(Name=fn, Stage="LIVE"))
    assert err["Code"] == "NoSuchFunctionExists", (
        f"DescribeFunction(Stage=LIVE) on a never-published function returned {err['Code']!r}, "
        f"expected NoSuchFunctionExists"
    )
    expected_msg = "The specified function does not exist."
    assert err.get("Message") == expected_msg, (
        f"DescribeFunction(Stage=LIVE) message {err.get('Message')!r}, expected {expected_msg!r}"
    )
    # Positive control: the DEVELOPMENT stage exists and runs.
    _assert_runs(cf, fn, "DEVELOPMENT")

    cfn.update_stack(StackName=stack, TemplateBody=_template(fn, True))
    _wait_stack_status(cfn, stack, "UPDATE_COMPLETE", timeout_s=600)

    phys_after = _physical_id(cfn, stack, "Fn")
    assert phys_after == phys_before, (
        f"toggling AutoPublish replaced the function: {phys_before!r} -> {phys_after!r}"
    )
    out_after = _outputs(cfn, stack)
    assert out_after["FunctionArn"] == out["FunctionArn"], (
        f"toggling AutoPublish changed FunctionARN {out['FunctionArn']!r} -> {out_after['FunctionArn']!r}"
    )
    assert out_after["Stage"] == "LIVE", f"after AutoPublish:true the stack reports Stage {out_after['Stage']!r}, expected LIVE"
    live = cf.describe_function(Name=fn, Stage="LIVE")["FunctionSummary"]
    assert live["FunctionMetadata"]["Stage"] == "LIVE", f"LIVE describe returned stage {live['FunctionMetadata']['Stage']!r}"
    assert live["Status"] == "UNASSOCIATED", (
        f"a published, distribution-less function reports Status {live['Status']!r}, expected UNASSOCIATED"
    )
    live_code = cf.get_function(Name=fn, Stage="LIVE")["FunctionCode"].read().decode()
    assert live_code == _CODE, f"LIVE stage code differs from the deployed code: {live_code!r}"
    _assert_runs(cf, fn, "LIVE")


def _assert_runs(cf, fn: str, stage: str) -> None:
    etag = cf.describe_function(Name=fn, Stage=stage)["ETag"]
    result = cf.test_function(Name=fn, IfMatch=etag, Stage=stage, EventObject=_EVENT)["TestResult"]
    err = result.get("FunctionErrorMessage")
    assert not err, f"{stage} function {fn!r} errored: {err!r} (logs: {result.get('FunctionExecutionLogs')!r})"
    req = json.loads(result["FunctionOutput"])["request"]
    assert req["uri"] == "/published/x", f"{stage} code rewrote the URI to {req['uri']!r}, expected '/published/x'"
    assert req["headers"]["x-deployed-by"]["value"] == "cfn", (
        f"{stage} code set x-deployed-by to {req['headers'].get('x-deployed-by')!r}, expected 'cfn'"
    )



def _client_error(fn) -> dict:
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None)
        if resp is None:
            raise
        return resp["Error"]
    raise AssertionError("call unexpectedly SUCCEEDED; expected an error")


def _outputs(cfn, stack: str) -> dict:
    s = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in s.get("Outputs", [])}


def _physical_id(cfn, stack: str, logical: str) -> str:
    return cfn.describe_stack_resource(StackName=stack, LogicalResourceId=logical)[
        "StackResourceDetail"]["PhysicalResourceId"]


def _wait_stack_status(cfn, stack: str, target: str, timeout_s: float = 600.0, interval_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        if status == target:
            return
        if status.endswith("FAILED") or status.endswith("ROLLBACK_COMPLETE"):
            events = []
            for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack):
                events.extend(page["StackEvents"])
            reasons = [f"{e['LogicalResourceId']}[{e['ResourceStatus']}]: {e.get('ResourceStatusReason', '')}"
                       for e in events if "FAILED" in e["ResourceStatus"]]
            raise AssertionError(f"stack {stack} entered {status} waiting for {target}: {reasons}")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack} never reached {target} within {timeout_s}s, last={status}")


def _delete_stack_and_verify(ctx, stack: str, fn_name: str) -> None:
    """Delete the stack, wait for DELETE_COMPLETE, then verify the function is gone. Never raises."""
    cfn = ctx.client("cloudformation")
    cf = ctx.client("cloudfront")
    try:
        cfn.delete_stack(StackName=stack)
        deadline = time.monotonic() + 900
        status = None
        while time.monotonic() < deadline:
            try:
                status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
            except Exception as exc:  # noqa: BLE001 -- "does not exist" once fully deleted
                if "does not exist" in str(exc):
                    status = "DELETE_COMPLETE"
                else:
                    raise
            if status in ("DELETE_COMPLETE", "DELETE_FAILED"):
                break
            time.sleep(10)
        if status != "DELETE_COMPLETE":
            raise RuntimeError(f"cloudformation stack {stack} ended in {status!r}")
        try:
            _client_error(lambda: cf.describe_function(Name=fn_name))
        except AssertionError:
            raise RuntimeError(
                f"cloudfront function {fn_name} still exists after stack delete"
            )
    except Exception as exc:  # noqa: BLE001
        teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
        if (
            teardown_code not in ("NoSuchFunctionExists",)
            and not any(t in teardown_code for t in ("NotFound", "NoSuch", "NonExistent", "DoesNotExist"))
        ):
            raise RuntimeError(f"teardown of stack {stack} failed: {exc!r}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
