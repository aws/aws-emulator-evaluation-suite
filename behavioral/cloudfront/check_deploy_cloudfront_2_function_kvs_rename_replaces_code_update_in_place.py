"""deploy-cloudfront-2-function-kvs-rename-replaces-code-update-in-place."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cloudfront-2-function-kvs-rename-replaces-code-update-in-place"
GROUP = "deploy-cfn-cloudfront-function-kvs"
SERVICES = ["cloudfront"]

# The two code versions differ in exactly the observable ways the assertions read back: the URI
# rewrite target and the x-code-version header. Both read the associated key-value store through
# `cf.kvs()`, which resolves the function's single KeyValueStoreAssociation, so the store's ARN never
# appears in the code: a function with no association has nothing for cf.kvs() to bind to.
_CODE_TEMPLATE = """import cf from 'cloudfront';
const kvs = cf.kvs();
async function handler(event) {
    var request = event.request;
    var hit = await kvs.exists('sim2real-probe-key');
    request.headers['x-kvs-probe'] = {value: hit ? 'present' : 'absent'};
    request.headers['x-code-version'] = {value: '%(version)s'};
    if (request.uri.endsWith('/')) {
        request.uri = request.uri + '%(index)s';
    }
    return request;
}
"""
_CODE_V1 = _CODE_TEMPLATE % {"version": "v1", "index": "index.html"}
_CODE_V2 = _CODE_TEMPLATE % {"version": "v2", "index": "default-v2.htm"}

_EVENT = json.dumps({
    "version": "1.0",
    "context": {"eventType": "viewer-request"},
    "viewer": {"ip": "203.0.113.7"},
    "request": {
        "method": "GET",
        "uri": "/docs/",
        "querystring": {},
        "headers": {"x-keep-me": {"value": "kept"}},
        "cookies": {},
    },
}).encode()


def _template(kvs_name: str, fn_name: str, code: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Store": {
                "Type": "AWS::CloudFront::KeyValueStore",
                "Properties": {"Name": kvs_name, "Comment": "sim2real deploy kvs"},
            },
            "Fn": {
                "Type": "AWS::CloudFront::Function",
                "Properties": {
                    "Name": fn_name,
                    "AutoPublish": True,
                    "FunctionCode": code,
                    "FunctionConfig": {
                        "Comment": "sim2real deploy function",
                        "Runtime": "cloudfront-js-2.0",
                        "KeyValueStoreAssociations": [
                            {"KeyValueStoreARN": {"Fn::GetAtt": ["Store", "Arn"]}}
                        ],
                    },
                },
            },
        },
        "Outputs": {
            "FunctionArn": {"Value": {"Fn::GetAtt": ["Fn", "FunctionARN"]}},
            "StoreArn": {"Value": {"Fn::GetAtt": ["Store", "Arn"]}},
        },
    })


@tags("axis:happy-path", "concern:deploy", "plane:control", "cap:c1")
def run(ctx) -> None:
    """CloudFormation replaces a CloudFront Function on a Name change and updates it in place on a
    FunctionCode change, and AutoPublish carries each deployed code version to the LIVE stage.
    """
    cfn = ctx.client("cloudformation")
    cf = ctx.client("cloudfront")
    account = ctx.client("sts").get_caller_identity()["Account"]

    stack = ctx.unique_name("sim2real-cfkvs-stack-")
    kvs_name = ctx.unique_name("sim2real-cfkvs-store-")
    fn_v1 = ctx.unique_name("sim2real-cfkvs-fn-a-")
    fn_v2 = ctx.unique_name("sim2real-cfkvs-fn-b-")

    cfn.create_stack(
        StackName=stack,
        TemplateBody=_template(kvs_name, fn_v1, _CODE_V1),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    # Registered before the first wait: a stack that never completes still has to go, and the
    # verifier checks that every function name this check could have created is gone afterwards.
    ctx.on_cleanup(lambda: _delete_stack_and_verify(ctx, stack, [fn_v1, fn_v2], kvs_name))
    _wait_stack_status(cfn, stack, "CREATE_COMPLETE", timeout_s=600)

    outputs = _outputs(cfn, stack)
    arn_v1 = outputs["FunctionArn"]
    store_arn = outputs["StoreArn"]
    phys_v1 = _physical_id(cfn, stack, "Fn")
    assert arn_v1 == f"arn:aws:cloudfront::{account}:function/{fn_v1}", (
        f"stack output FunctionARN is {arn_v1!r}, expected the ARN of {fn_v1!r} in account {account}"
    )

    # The association the template declared is the one the deployed function carries.
    dev = cf.describe_function(Name=fn_v1, Stage="DEVELOPMENT")
    assoc = dev["FunctionSummary"]["FunctionConfig"]["KeyValueStoreAssociations"]
    assert assoc["Quantity"] == 1 and assoc["Items"][0]["KeyValueStoreARN"] == store_arn, (
        f"deployed function's KeyValueStoreAssociations is {assoc!r}, expected exactly {store_arn!r}"
    )
    assert dev["FunctionSummary"]["FunctionConfig"]["Runtime"] == "cloudfront-js-2.0", (
        f"deployed runtime is {dev['FunctionSummary']['FunctionConfig']['Runtime']!r}"
    )

    # AutoPublish: the LIVE stage exists right after CREATE_COMPLETE. A
    # published function with no distribution association reports Status UNASSOCIATED (an
    # unpublished one reports UNPUBLISHED and has no LIVE stage at all); the stage is in
    # FunctionMetadata.Stage, not in Status.
    live = cf.describe_function(Name=fn_v1, Stage="LIVE")["FunctionSummary"]
    assert live["FunctionMetadata"]["Stage"] == "LIVE", (
        f"DescribeFunction(Stage=LIVE) returned stage {live['FunctionMetadata']['Stage']!r}"
    )
    assert live["Status"] == "UNASSOCIATED", (
        f"an auto-published, distribution-less function reports Status {live['Status']!r}, "
        f"expected 'UNASSOCIATED' (published to LIVE, not attached to any distribution)"
    )
    live_code = cf.get_function(Name=fn_v1, Stage="LIVE")["FunctionCode"].read().decode()
    assert live_code == _CODE_V1, f"LIVE stage code differs from the deployed v1 code: {live_code!r}"

    out = _test(cf, fn_v1, "DEVELOPMENT")
    _assert_output(out, version="v1", uri="/docs/index.html")

    # ---- Update 1: change Name only -> replacement ------------------------------------------
    cfn.update_stack(StackName=stack, TemplateBody=_template(kvs_name, fn_v2, _CODE_V1))
    _wait_stack_status(cfn, stack, "UPDATE_COMPLETE", timeout_s=600)

    arn_v2 = _outputs(cfn, stack)["FunctionArn"]
    phys_v2 = _physical_id(cfn, stack, "Fn")
    assert phys_v2 != phys_v1, (
        f"renaming the function kept physical id {phys_v1!r}; Name is create-only, so the "
        f"function must be REPLACED"
    )
    assert arn_v2 == f"arn:aws:cloudfront::{account}:function/{fn_v2}" and arn_v2 != arn_v1, (
        f"after the rename FunctionARN is {arn_v2!r} (was {arn_v1!r}), expected the ARN of {fn_v2!r}"
    )
    replace_events = [
        e for e in _events(cfn, stack)
        if e["LogicalResourceId"] == "Fn" and e["ResourceStatus"] == "DELETE_COMPLETE"
        and e.get("PhysicalResourceId") == phys_v1
    ]
    assert len(replace_events) == 1, (
        f"expected exactly one DELETE_COMPLETE event for the replaced function {phys_v1!r}, "
        f"got {len(replace_events)}"
    )
    err = _client_error(lambda: cf.get_function(Name=fn_v1))
    assert err["Code"] == "NoSuchFunctionExists", (
        f"GetFunction on the replaced function's old name {fn_v1!r} returned {err['Code']!r}, expected "
        f"NoSuchFunctionExists -- the replaced function must be deleted"
    )
    expected_msg = "The specified function does not exist."
    assert err.get("Message") == expected_msg, (
        f"GetFunction({fn_v1!r}) message {err.get('Message')!r}, expected {expected_msg!r}"
    )
    # Positive control for the negative above: the same call on the new name succeeds, and the
    # replacement still carries the association and still runs.
    new_dev = cf.describe_function(Name=fn_v2, Stage="DEVELOPMENT")["FunctionSummary"]
    new_assoc = new_dev["FunctionConfig"]["KeyValueStoreAssociations"]
    assert new_assoc["Quantity"] == 1 and new_assoc["Items"][0]["KeyValueStoreARN"] == store_arn, (
        f"replacement function's associations are {new_assoc!r}, expected exactly {store_arn!r}"
    )
    out = _test(cf, fn_v2, "DEVELOPMENT")
    _assert_output(out, version="v1", uri="/docs/index.html")

    # ---- Update 2: change FunctionCode only -> in-place update -------------------------------
    etag_before = cf.describe_function(Name=fn_v2, Stage="DEVELOPMENT")["ETag"]
    cfn.update_stack(StackName=stack, TemplateBody=_template(kvs_name, fn_v2, _CODE_V2))
    _wait_stack_status(cfn, stack, "UPDATE_COMPLETE", timeout_s=600)

    arn_v3 = _outputs(cfn, stack)["FunctionArn"]
    phys_v3 = _physical_id(cfn, stack, "Fn")
    assert phys_v3 == phys_v2, (
        f"a code-only update changed the physical id {phys_v2!r} -> {phys_v3!r}; FunctionCode is "
        f"mutable, so the function must be updated in place"
    )
    assert arn_v3 == arn_v2, f"a code-only update changed FunctionARN {arn_v2!r} -> {arn_v3!r}"
    etag_after = cf.describe_function(Name=fn_v2, Stage="DEVELOPMENT")["ETag"]
    assert etag_after != etag_before, (
        f"the DEVELOPMENT ETag stayed {etag_before!r} across a code update -- nothing was written"
    )

    out = _test(cf, fn_v2, "DEVELOPMENT")
    _assert_output(out, version="v2", uri="/docs/default-v2.htm")
    # AutoPublish re-publishes on update: LIVE now runs the new code too.
    live_code = cf.get_function(Name=fn_v2, Stage="LIVE")["FunctionCode"].read().decode()
    assert live_code == _CODE_V2, f"LIVE stage code was not re-published after the code update: {live_code!r}"
    out = _test(cf, fn_v2, "LIVE")
    _assert_output(out, version="v2", uri="/docs/default-v2.htm")


def _test(cf, name: str, stage: str) -> dict:
    etag = cf.describe_function(Name=name, Stage=stage)["ETag"]
    result = cf.test_function(Name=name, IfMatch=etag, Stage=stage, EventObject=_EVENT)["TestResult"]
    # Real CloudFront reports "no error" as an empty string; checked before parsing the output so a
    # runtime error is readable rather than masked by a JSON decode failure.
    err = result.get("FunctionErrorMessage")
    assert not err, (
        f"{stage} function {name!r} errored: {err!r} (logs: {result.get('FunctionExecutionLogs')!r})"
    )
    return json.loads(result["FunctionOutput"])


def _assert_output(out: dict, *, version: str, uri: str) -> None:
    req = out["request"]
    headers = req["headers"]
    assert req["uri"] == uri, f"deployed {version} code rewrote the URI to {req['uri']!r}, expected {uri!r}"
    assert headers["x-code-version"]["value"] == version, (
        f"x-code-version header is {headers.get('x-code-version')!r}, expected {version!r}"
    )
    assert headers["x-kvs-probe"]["value"] == "absent", (
        f"the KVS probe header is {headers.get('x-kvs-probe')!r}; the store is empty, so the "
        f"associated-store lookup must report 'absent'"
    )
    assert headers["x-keep-me"]["value"] == "kept", f"an untouched header was altered: {headers.get('x-keep-me')!r}"



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


def _outputs(cfn, stack: str) -> dict:
    s = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in s.get("Outputs", [])}


def _physical_id(cfn, stack: str, logical: str) -> str:
    return cfn.describe_stack_resource(StackName=stack, LogicalResourceId=logical)[
        "StackResourceDetail"]["PhysicalResourceId"]


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


def _delete_stack_and_verify(ctx, stack: str, fn_names: list[str], kvs_name: str) -> None:
    """Delete the stack, wait for DELETE_COMPLETE, then verify nothing it owned survives; raises
    on failure."""
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
    probes = [(f"cloudfront function {n}", lambda n=n: cf.describe_function(Name=n),
               "NoSuchFunctionExists") for n in fn_names]
    probes.append((f"cloudfront key-value store {kvs_name}",
                   lambda: cf.describe_key_value_store(Name=kvs_name), "EntityNotFound"))
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
