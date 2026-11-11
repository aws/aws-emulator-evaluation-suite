"""deploy-lambda-layerversionpermission-principal-malformed-rejected."""
from __future__ import annotations

import io
import json
import re
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-lambda-layerversionpermission-principal-malformed-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda", "s3"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

_KEY = "layer.zip"
_BAD_PRINCIPAL = "not-an-account"
_REJECTED = (
    f"1 validation error detected: Value '{_BAD_PRINCIPAL}' at 'principal' failed to satisfy "
    r"constraint: Member must satisfy regular expression pattern: \d{12}|\*|"
    r"arn:(aws[a-zA-Z-]*):iam::\d{12}:root (Service: Lambda, Status Code: 400, "
    "Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)


def _template(bucket, layer_name, principal, with_permission=True):
    resources = {
        "Layer": {
            "Type": "AWS::Lambda::LayerVersion",
            "Properties": {
                "LayerName": layer_name,
                "Description": "sim2real layer",
                "CompatibleRuntimes": ["python3.13"],
                "Content": {"S3Bucket": bucket, "S3Key": _KEY},
            },
        },
    }
    outputs = {"LayerArnOut": {"Value": {"Fn::GetAtt": ["Layer", "LayerVersionArn"]}}}
    if with_permission:
        resources["LayerPermission"] = {
            "Type": "AWS::Lambda::LayerVersionPermission",
            "Properties": {
                "LayerVersionArn": {"Fn::GetAtt": ["Layer", "LayerVersionArn"]},
                "Action": "lambda:GetLayerVersion",
                "Principal": principal,
            },
        }
        outputs["PermissionIdOut"] = {"Value": {"Ref": "LayerPermission"}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": outputs,
    })


def _stage_zip(ctx, s3, bucket):
    """A tagged bucket holding the layer zip; its cleanup empties and deletes it."""
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": bucket}]})
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("python/sim2real_marker.py", "MARKER = 1\n")
    s3.put_object(Bucket=bucket, Key=_KEY, Body=buf.getvalue())


def _empty_and_delete_bucket(s3, name):
    """Delete every object, then the bucket; a bucket already gone is done."""
    try:
        for obj in paginate(s3, "list_objects_v2", "Contents", Bucket=name):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _versions(lam, layer_name):
    """``(LayerVersionArn, Version)`` of every listed version of ``layer_name`` (all pages)."""
    return [(v["LayerVersionArn"], v["Version"])
            for v in paginate(lam, "list_layer_versions", "LayerVersions", LayerName=layer_name)]


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation LayerVersionPermission whose Principal is not an account rolls back.

    Lambda refuses the Principal and lists no version of the layer, while the same template with
    the caller's account id grants a permission that reads back.
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cfn-lvpneg-")
    good_layer = ctx.unique_name("sim2real-cfn-lvpneg-good-layer-")
    bad_layer = ctx.unique_name("sim2real-cfn-lvpneg-bad-layer-")

    _stage_zip(ctx, s3, bucket)
    # Positive control: the same template, the one property (Principal) given a VALID value.
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfn-lvpneg-goodstack-"),
                           _template(bucket, good_layer, ctx.account))
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfn-lvpneg-badstack-"),
                          _template(bucket, bad_layer, _BAD_PRINCIPAL))
    partition = good_id.split(":")[1]

    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    got = handler_reason(failed_reason(stack_events(cfn, bad_id), "LayerPermission"),
                         ctx.account, bad_layer)
    assert got == _REJECTED, f"LayerPermission reason {got!r}, expected {_REJECTED!r}"
    # Rollback absence through Lambda: no version of the layer is listed, nor is the version's
    # policy readable, before any delete.
    assert _versions(lam, bad_layer) == [], f"rolled-back layer versions {_versions(lam, bad_layer)!r}"
    bad_arn = f"arn:{partition}:lambda:{ctx.region}:{ctx.account}:layer:{bad_layer}:1"
    version_gone = ("ResourceNotFoundException", f"Layer version {bad_arn} does not exist.")
    expect_error(lambda: lam.get_layer_version_policy(LayerName=bad_layer, VersionNumber=1),
                 *version_gone)

    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    good_arn = stack_outputs(cfn, good_id)["LayerArnOut"]
    assert _versions(lam, good_layer) == [(good_arn, 1)], f"control layer {good_arn!r} not listed"
    statements = json.loads(lam.get_layer_version_policy(
        LayerName=good_layer, VersionNumber=1)["Policy"])["Statement"]
    got = [(s["Action"], s["Principal"]) for s in statements]
    assert got == [("lambda:GetLayerVersion",
                    {"AWS": f"arn:{partition}:iam::{ctx.account}:root"})], (
        f"control statements {statements!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
