"""deploy-cloudfront-2-function-second-kvs-association-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cloudfront-2-function-second-kvs-association-rejected"
GROUP = "deploy-cfn-cloudfront-function-kvs"
SERVICES = ["cloudfront"]

_CODE = """import cf from 'cloudfront';
const kvs = cf.kvs();
async function handler(event) {
    var request = event.request;
    var hit = await kvs.exists('sim2real-probe-key');
    request.headers['x-kvs-probe'] = {value: hit ? 'present' : 'absent'};
    request.uri = '/assoc-ok';
    return request;
}
"""

_EVENT = json.dumps({
    "version": "1.0",
    "context": {"eventType": "viewer-request"},
    "viewer": {"ip": "203.0.113.8"},
    "request": {"method": "GET", "uri": "/", "querystring": {}, "headers": {}, "cookies": {}},
}).encode()


def _template(fn_name: str, kvs_a: str, kvs_b: str | None) -> str:
    resources = {
        "StoreA": {
            "Type": "AWS::CloudFront::KeyValueStore",
            "Properties": {"Name": kvs_a, "Comment": "sim2real deploy kvs a"},
        },
    }
    assocs = [{"KeyValueStoreARN": {"Fn::GetAtt": ["StoreA", "Arn"]}}]
    if kvs_b is not None:
        resources["StoreB"] = {
            "Type": "AWS::CloudFront::KeyValueStore",
            "Properties": {"Name": kvs_b, "Comment": "sim2real deploy kvs b"},
        }
        assocs.append({"KeyValueStoreARN": {"Fn::GetAtt": ["StoreB", "Arn"]}})
    resources["Fn"] = {
        "Type": "AWS::CloudFront::Function",
        "Properties": {
            "Name": fn_name,
            "AutoPublish": True,
            "FunctionCode": _CODE,
            "FunctionConfig": {
                "Comment": "sim2real deploy function",
                "Runtime": "cloudfront-js-2.0",
                "KeyValueStoreAssociations": assocs,
            },
        },
    }
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": {"StoreAArn": {"Value": {"Fn::GetAtt": ["StoreA", "Arn"]}}},
    })


@tags("axis:rejection", "concern:deploy", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """A stack update giving a CloudFront Function a second key-value store association is rejected
    and rolled back, leaving the function unchanged and deleting the added store; UpdateFunction
    returns the same limit error directly.
    """
    cfn = ctx.client("cloudformation")
    cf = ctx.client("cloudfront")

    stack = ctx.unique_name("sim2real-cfkvs2-stack-")
    kvs_a = ctx.unique_name("sim2real-cfkvs2-a-")
    kvs_b = ctx.unique_name("sim2real-cfkvs2-b-")
    fn = ctx.unique_name("sim2real-cfkvs2-fn-")

    cfn.create_stack(StackName=stack, TemplateBody=_template(fn, kvs_a, None),
                     Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_stack_and_verify(ctx, stack, fn, [kvs_a, kvs_b]))
    _wait_stack_status(cfn, stack, "CREATE_COMPLETE", timeout_s=600)

    store_a_arn = {o["OutputKey"]: o["OutputValue"]
                   for o in cfn.describe_stacks(StackName=stack)["Stacks"][0]["Outputs"]}["StoreAArn"]

    # Positive control: one association deploys and the function runs against it.
    before = cf.describe_function(Name=fn, Stage="DEVELOPMENT")
    assoc = before["FunctionSummary"]["FunctionConfig"]["KeyValueStoreAssociations"]
    assert assoc["Quantity"] == 1 and assoc["Items"][0]["KeyValueStoreARN"] == store_a_arn, (
        f"single-association deploy produced {assoc!r}, expected exactly {store_a_arn!r}"
    )
    _assert_runs(cf, fn)
    etag_before = before["ETag"]
    live_etag_before = cf.describe_function(Name=fn, Stage="LIVE")["ETag"]

    # Break exactly one thing: a second store, associated with the same function.
    cfn.update_stack(StackName=stack, TemplateBody=_template(fn, kvs_a, kvs_b))
    final = _wait_stack_terminal(cfn, stack, timeout_s=900)
    assert final == "UPDATE_ROLLBACK_COMPLETE", (
        f"a two-association update ended in {final!r}, expected UPDATE_ROLLBACK_COMPLETE"
    )
    fn_failures = [e for e in _events(cfn, stack)
                   if e["LogicalResourceId"] == "Fn" and e["ResourceStatus"] == "UPDATE_FAILED"]
    assert len(fn_failures) == 1, (
        f"expected exactly one UPDATE_FAILED event on Fn, got "
        f"{[(e['ResourceStatus'], e.get('ResourceStatusReason')) for e in fn_failures]!r}"
    )
    reason = fn_failures[0].get("ResourceStatusReason", "")
    handler_code = re.search(r"HandlerErrorCode: (\w+)", reason)
    assert handler_code is not None and handler_code.group(1) == "InvalidRequest", (
        f"Fn UPDATE_FAILED reason carried handler code "
        f"{handler_code.group(1) if handler_code else None!r}, expected 'InvalidRequest': {reason!r}"
    )
    # The handler's RequestToken, the CloudFront Request ID and the SDK attempt count vary per
    # call; every other character of the reason is fixed.
    varying = re.search(
        r"Request ID: ([0-9a-f-]+)\) \(SDK Attempt Count: (\d+)\)\" \(RequestToken: ([0-9a-f-]+),", reason
    )
    request_id, attempts, token = varying.groups() if varying else (None, None, None)
    expected_reason = (
        'Resource handler returned message: "Invalid request provided: AWS::CloudFront::Function: '
        "The parameter KeyValueStoreAssociations is invalid; too many KeyValueStore associations "
        f"per Function. (Service: CloudFront, Status Code: 400, Request ID: {request_id}) "
        f'(SDK Attempt Count: {attempts})" (RequestToken: {token}, HandlerErrorCode: InvalidRequest)'
    )
    assert reason == expected_reason, (
        f"Fn UPDATE_FAILED reason {reason!r}, expected {expected_reason!r}"
    )

    # Effect absent: nothing about the deployed function moved.
    after = cf.describe_function(Name=fn, Stage="DEVELOPMENT")
    assoc_after = after["FunctionSummary"]["FunctionConfig"]["KeyValueStoreAssociations"]
    assert assoc_after == assoc, f"the rejected update changed the associations: {assoc!r} -> {assoc_after!r}"
    assert after["ETag"] == etag_before, (
        f"the rejected update changed the DEVELOPMENT ETag {etag_before!r} -> {after['ETag']!r}"
    )
    live_etag_after = cf.describe_function(Name=fn, Stage="LIVE")["ETag"]
    assert live_etag_after == live_etag_before, (
        f"the rejected update re-published LIVE: ETag {live_etag_before!r} -> {live_etag_after!r}"
    )
    # The rollback must delete the store the failed update created.
    gone = _client_error(lambda: cf.describe_key_value_store(Name=kvs_b))
    assert gone["Code"] == "EntityNotFound", (
        f"DescribeKeyValueStore on the rolled-back store {kvs_b!r} returned {gone['Code']!r}, expected EntityNotFound"
    )
    expected_msg = "The specified KeyValueStore does not exist."
    assert gone.get("Message") == expected_msg, (
        f"DescribeKeyValueStore({kvs_b!r}) message {gone.get('Message')!r}, expected {expected_msg!r}"
    )
    _assert_runs(cf, fn)

    # The same limit at its source: the exact error UpdateFunction returns for two associations.
    # The second store is created directly (CFN deleted its own), with cleanup registered at once.
    created = cf.create_key_value_store(Name=kvs_b, Comment="sim2real direct second store")
    store_b_arn = created["KeyValueStore"]["ARN"]
    ctx.on_cleanup(lambda: _delete_kvs(cf, kvs_b))
    _wait_kvs_ready(cf, kvs_b)
    err = _client_error(lambda: cf.update_function(
        Name=fn, IfMatch=etag_before, FunctionCode=_CODE.encode(),
        FunctionConfig={
            "Comment": "sim2real deploy function", "Runtime": "cloudfront-js-2.0",
            "KeyValueStoreAssociations": {"Quantity": 2, "Items": [
                {"KeyValueStoreARN": store_a_arn}, {"KeyValueStoreARN": store_b_arn}]},
        },
    ))
    assert err["Code"] == "InvalidArgument", (
        f"UpdateFunction with two KeyValueStoreAssociations returned {err['Code']!r}, expected InvalidArgument"
    )
    expected_msg = "The parameter KeyValueStoreAssociations is invalid; too many KeyValueStore associations per Function."
    assert err.get("Message") == expected_msg, (
        f"UpdateFunction with two associations message {err.get('Message')!r}, expected {expected_msg!r}"
    )
    still = cf.describe_function(Name=fn, Stage="DEVELOPMENT")
    assert still["ETag"] == etag_before, (
        f"the rejected UpdateFunction still wrote: ETag {etag_before!r} -> {still['ETag']!r}"
    )


def _assert_runs(cf, fn: str) -> None:
    etag = cf.describe_function(Name=fn, Stage="DEVELOPMENT")["ETag"]
    result = cf.test_function(Name=fn, IfMatch=etag, Stage="DEVELOPMENT", EventObject=_EVENT)["TestResult"]
    err = result.get("FunctionErrorMessage")
    assert not err, f"function {fn!r} errored: {err!r} (logs: {result.get('FunctionExecutionLogs')!r})"
    req = json.loads(result["FunctionOutput"])["request"]
    assert req["uri"] == "/assoc-ok", f"function rewrote the URI to {req['uri']!r}, expected '/assoc-ok'"
    assert req["headers"]["x-kvs-probe"]["value"] == "absent", (
        f"associated-store probe returned {req['headers'].get('x-kvs-probe')!r}, expected 'absent'"
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


def _error_code(fn) -> str:
    return _client_error(fn)["Code"]


def _events(cfn, stack: str) -> list[dict]:
    events = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack):
        events.extend(page["StackEvents"])
    return events


def _wait_stack_status(cfn, stack: str, target: str, timeout_s: float = 600.0, interval_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        if status == target:
            return
        if status.endswith("FAILED") or status.endswith("ROLLBACK_COMPLETE"):
            reasons = [
                f"{e['LogicalResourceId']}[{e['ResourceStatus']}]: {e.get('ResourceStatusReason', '')}"
                for e in _events(cfn, stack) if "FAILED" in e["ResourceStatus"]
            ]
            raise AssertionError(f"stack {stack} entered {status} waiting for {target}: {reasons}")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack} never reached {target} within {timeout_s}s, last={status}")


def _wait_stack_terminal(cfn, stack: str, timeout_s: float = 900.0, interval_s: float = 5.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        if not status.endswith("_IN_PROGRESS"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack} still in progress after {timeout_s}s, last={status}")


def _wait_kvs_ready(cf, name: str, timeout_s: float = 300.0) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cf.describe_key_value_store(Name=name)["KeyValueStore"]["Status"]
        if status == "READY":
            return
        time.sleep(5)
    raise AssertionError(f"key-value store {name} never reached READY, last={status!r}")


def _delete_kvs(cf, name: str) -> None:
    try:
        cf.delete_key_value_store(Name=name, IfMatch=cf.describe_key_value_store(Name=name)["ETag"])
    except Exception as exc:  # noqa: BLE001
        if getattr(exc, "response", {}).get("Error", {}).get("Code") != "EntityNotFound":
            raise RuntimeError(f"cloudfront key-value store {name}: {exc!r}") from exc


def _delete_stack_and_verify(ctx, stack: str, fn_name: str, kvs_names: list[str]) -> None:
    """Delete the stack, wait for DELETE_COMPLETE, then verify the function and stores are gone;
    raises on failure."""
    cfn = ctx.client("cloudformation")
    cf = ctx.client("cloudfront")
    cfn.delete_stack(StackName=stack)
    deadline = time.monotonic() + 900
    status = None
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        except ClientError as exc:  # "does not exist" once fully deleted
            if "does not exist" not in str(exc):
                raise
            status = "DELETE_COMPLETE"
        if status in ("DELETE_COMPLETE", "DELETE_FAILED"):
            break
        time.sleep(2)
    if status != "DELETE_COMPLETE":
        raise RuntimeError(f"cloudformation stack {stack} ended in {status!r}")
    probes = [(f"cloudfront function {fn_name}", lambda: cf.describe_function(Name=fn_name),
               "NoSuchFunctionExists")]
    # kvs_b may legitimately still exist here: the direct-API store has its own cleanup, which
    # runs before this one (LIFO). Report only what survives that.
    probes += [(f"cloudfront key-value store {n}", lambda n=n: cf.describe_key_value_store(Name=n),
                "EntityNotFound") for n in kvs_names]
    leaks = []
    for label, probe, gone in probes:
        try:
            code = _error_code(probe)
        except AssertionError:
            leaks.append(f"{label} still exists after teardown")
            continue
        if code != gone:
            leaks.append(f"{label}: describe answered {code!r}, not {gone!r}")
    if leaks:
        raise RuntimeError("; ".join(leaks))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
