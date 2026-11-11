"""cfn-synthetics-canary-properties-and-getatt-read-back-then-resources-removed-on-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-synthetics-canary-properties-and-getatt-read-back-then-resources-removed-on-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "synthetics"]

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


def until_raises(fn, timeout_s=90.0):
    """Poll ``fn()`` every 2 s until it raises a ClientError (an eventually consistent delete).

    Grade the error afterwards with expect_error; a success past the deadline fails.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"still answering after {timeout_s:.0f}s: {result!r}")
        time.sleep(2)


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

_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
}
_SCRIPT = (
    'const log = require("SyntheticsLogger");\n'
    'const handler = async () => { log.info("sim2real canary run"); };\n'
    'exports.handler = async () => { return await handler(); };\n'
)


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    """Remove every object version in ``bucket``, then delete it; a missing bucket is a no-op."""
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]}
                    for v in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objs:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


@tags("axis:happy-path", "cap:c7", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::Synthetics::Canary is real at Synthetics: Ref, GetAtt and every
    declared property match Synthetics' own answer, the canary stays READY (never started), and
    deleting the stack removes it with its provisioned resources cleaned up automatically."""
    cfn = ctx.client("cloudformation")
    syn = ctx.client("synthetics")
    s3 = ctx.client("s3")

    bucket_name = ctx.unique_name("sim2real-behav-syncny-")
    role_name = ctx.unique_name("sim2real-behav-syncny-role-")
    canary_name = ctx.unique_name("sim2real-behav-syncny-")
    template = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Bucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {"BucketName": bucket_name},
            },
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": _TRUST_POLICY,
                },
            },
            "Canary": {
                "Type": "AWS::Synthetics::Canary",
                "Properties": {
                    "Name": canary_name,
                    "Code": {"Handler": "index.handler", "Script": _SCRIPT},
                    "ArtifactS3Location": {"Fn::Sub": "s3://${Bucket}"},
                    "ExecutionRoleArn": {"Fn::GetAtt": ["Role", "Arn"]},
                    "Schedule": {"Expression": "rate(0 minute)"},
                    "RuntimeVersion": "syn-nodejs-puppeteer-9.0",
                    "StartCanaryAfterCreation": False,
                    # The canary's own Lambda function and layer go with it on delete.
                    "ProvisionedResourceCleanup": "AUTOMATIC",
                },
            },
        },
        "Outputs": {
            "CanaryName": {"Value": {"Ref": "Canary"}},
            "CanaryId": {"Value": {"Fn::GetAtt": ["Canary", "Id"]}},
            "CanaryState": {"Value": {"Fn::GetAtt": ["Canary", "State"]}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
        },
    })

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-cfn-syncny-"), template,
                            Capabilities=["CAPABILITY_NAMED_IAM"])
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)

    # Ref against an independent DescribeCanaries read filtered to the declared name.
    listed = [c["Name"] for c in syn.describe_canaries(Names=[canary_name]).get("Canaries", [])]
    assert listed == [outputs["CanaryName"]], (
        f"DescribeCanaries {listed!r} for Ref {outputs['CanaryName']!r}"
    )
    canary = syn.get_canary(Name=canary_name)["Canary"]
    got = {
        "Id": canary["Id"],
        "State": canary["Status"]["State"],
        "ExecutionRoleArn": canary["ExecutionRoleArn"],
        "Handler": canary["Code"].get("Handler"),
        "ArtifactS3Location": canary.get("ArtifactS3Location"),
        "Schedule": canary["Schedule"].get("Expression"),
        "RuntimeVersion": canary.get("RuntimeVersion"),
        "ProvisionedResourceCleanup": canary.get("ProvisionedResourceCleanup"),
    }
    want = {
        "Id": outputs["CanaryId"],
        "State": outputs["CanaryState"],
        "ExecutionRoleArn": outputs["RoleArn"],
        "Handler": "index.handler",
        # Synthetics stores the location without the s3:// scheme or a trailing slash, and the
        # never-run rate(0 minute) schedule as rate(0 hour).
        "ArtifactS3Location": bucket_name,
        "Schedule": "rate(0 hour)",
        "RuntimeVersion": "syn-nodejs-puppeteer-9.0",
        "ProvisionedResourceCleanup": "AUTOMATIC",
    }
    assert got == want and want["State"] == "READY", f"GetCanary {got!r}, expected {want!r}"

    delete_stack(cfn, stack_id)
    until_raises(lambda: syn.get_canary(Name=canary_name))
    gone = ("ResourceNotFoundException", "Canary not found.")
    expect_error(lambda: syn.get_canary(Name=canary_name), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
