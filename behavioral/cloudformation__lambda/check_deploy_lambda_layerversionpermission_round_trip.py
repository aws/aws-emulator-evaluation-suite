"""deploy-lambda-layerversionpermission-round-trip."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-lambda-layerversionpermission-round-trip"
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


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation LayerVersionPermission grants the declared account access to the layer.

    The layer and its grant read back through Lambda; an update dropping the grant removes it
    while the layer stays, and the stack delete removes the layer too.
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cfn-lvp-")
    layer_name = ctx.unique_name("sim2real-cfn-lvp-layer-")

    _stage_zip(ctx, s3, bucket)
    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfn-lvp-"),
                            _template(bucket, layer_name, ctx.account))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    partition = stack_id.split(":")[1]
    out = stack_outputs(cfn, stack_id)
    layer_arn = f"arn:{partition}:lambda:{ctx.region}:{ctx.account}:layer:{layer_name}:1"

    # GetAtt against an independent read: the one version ListLayerVersions shows.
    assert _versions(lam, layer_name) == [(layer_arn, 1)] and out["LayerArnOut"] == layer_arn, (
        f"listed versions {_versions(lam, layer_name)!r}, GetAtt {out['LayerArnOut']!r}"
    )
    layer = lam.get_layer_version_by_arn(Arn=layer_arn)
    assert (layer.get("Description"), layer["CompatibleRuntimes"]) == (
        "sim2real layer", ["python3.13"]), f"layer version {layer!r}"

    # The grant: one statement for the declared account; Ref is <LayerVersionArn>#<Sid>.
    statements = json.loads(lam.get_layer_version_policy(
        LayerName=layer_name, VersionNumber=1)["Policy"])["Statement"]
    got = [(s["Action"], s["Principal"], s["Effect"]) for s in statements]
    assert got == [("lambda:GetLayerVersion", {"AWS": f"arn:{partition}:iam::{ctx.account}:root"},
                    "Allow")], f"layer policy statements {statements!r}"
    assert out["PermissionIdOut"] == f"{layer_arn}#{statements[0]['Sid']}", (
        f"Ref {out['PermissionIdOut']!r}, statement Sid {statements[0]['Sid']!r}"
    )

    # Child before parent: an update drops only the permission; the same layer version stays.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(
        bucket, layer_name, ctx.account, with_permission=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"permission-dropping update ended {status!r}"
    policy_gone = ("ResourceNotFoundException",
                   f"Layer version {layer_arn} does not have any resource policy.")
    expect_error(lambda: lam.get_layer_version_policy(LayerName=layer_name, VersionNumber=1),
                 *policy_gone)
    after = lam.get_layer_version_by_arn(Arn=layer_arn)
    assert (after["LayerVersionArn"], after["CreatedDate"]) == (layer_arn, layer["CreatedDate"]), (
        f"the layer version after only its permission was dropped: {after!r}"
    )

    delete_stack(cfn, stack_id)
    layer_gone = ("ResourceNotFoundException", "The resource you requested does not exist.")
    expect_error(lambda: lam.get_layer_version_by_arn(Arn=layer_arn), *layer_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
