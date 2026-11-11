"""deploy-cfn-lakeformation-resource-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-lakeformation-resource-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam", "lakeformation", "s3"]

# ---- CloudFormation helpers: copy VERBATIM; delete the ones the check never calls. ----

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

_GONE = ("EntityNotFoundException", "Entity not found")
_NO_BUCKET = ("404", "Not Found")


def _s3_access(partition: str, bucket: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:DeleteObject"],
            "Resource": [f"arn:{partition}:s3:::{bucket}", f"arn:{partition}:s3:::{bucket}/*"],
        }],
    }


def _template(bucket: str, role_name: str, role_arn) -> str:
    """A bucket, a role that may read and write it, and the bucket registered with ``role_arn``."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": bucket}},
            "ResourceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "lakeformation.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                    "Policies": [{
                        "PolicyName": "s3access",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket",
                                           "s3:DeleteObject"],
                                "Resource": [
                                    {"Fn::Sub": "arn:${AWS::Partition}:s3:::${Bucket}"},
                                    {"Fn::Sub": "arn:${AWS::Partition}:s3:::${Bucket}/*"},
                                ],
                            }],
                        },
                    }],
                },
            },
            "LFResource": {
                "Type": "AWS::LakeFormation::Resource",
                "DependsOn": ["ResourceRole", "Bucket"],
                "Properties": {
                    "ResourceArn": {"Fn::Sub": "arn:${AWS::Partition}:s3:::${Bucket}"},
                    "RoleArn": role_arn,
                    "UseServiceLinkedRole": False,
                },
            },
        },
        "Outputs": {
            "LFResourceId": {"Value": {"Ref": "LFResource"}},
            "ResourceRoleArn": {"Value": {"Fn::GetAtt": ["ResourceRole", "Arn"]}},
        },
    })


def _registered(lf) -> dict[str, str]:
    """{ResourceArn: RoleArn} of every registered resource, all pages (the op has no paginator)."""
    kw, out = {}, {}
    while True:
        page = lf.list_resources(**kw)
        out.update({r["ResourceArn"]: r.get("RoleArn") for r in page["ResourceInfoList"]})
        if not page.get("NextToken"):
            return out
        kw["NextToken"] = page["NextToken"]


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::LakeFormation::Resource registers an S3 bucket at Lake Formation.

    Ref is the bucket ARN Lake Formation lists with the declared role, whose inline policy IAM
    reads back; the stack delete deregisters it and removes the bucket and role.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lakeformation-resource.html
    """
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    lf = ctx.client("lakeformation")
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-lfres-").lower()
    role_name = ctx.unique_name("sim2real-behav-lfres-role-")

    stack_id = create_stack(
        ctx, cfn, ctx.unique_name("sim2real-behav-cfn-lfres-"),
        _template(bucket, role_name, {"Fn::GetAtt": ["ResourceRole", "Arn"]}),
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]
    resource_arn = f"arn:{partition}:s3:::{bucket}"
    role = iam.get_role(RoleName=role_name)["Role"]
    assert outputs["ResourceRoleArn"] == role["Arn"], f"GetAtt role Arn {outputs!r}"
    policy = iam.get_role_policy(RoleName=role_name, PolicyName="s3access")["PolicyDocument"]
    assert policy == _s3_access(partition, bucket), f"inline policy reads {policy!r}"
    s3.head_bucket(Bucket=bucket)  # presence: HeadBucket raises unless the bucket exists

    # Ref against an independent read: the resources Lake Formation lists, every page.
    listed = {k: v for k, v in _registered(lf).items() if k == resource_arn}
    assert listed == {outputs["LFResourceId"]: role["Arn"]}, (
        f"Lake Formation lists {listed!r}; Ref is {outputs['LFResourceId']!r}"
    )
    # ListResources (above) names the ResourceArn; DescribeResource's ResourceInfo omits it.
    info = lf.describe_resource(ResourceArn=resource_arn)["ResourceInfo"]
    got = (info.get("RoleArn"), info.get("HybridAccessEnabled"), info.get("VerificationStatus"))
    assert got == (role["Arn"], False, "VERIFIED"), f"DescribeResource {info!r}"

    delete_stack(cfn, stack_id)
    expect_error(lambda: lf.describe_resource(ResourceArn=resource_arn), *_GONE)
    expect_error(lambda: s3.head_bucket(Bucket=bucket), *_NO_BUCKET)
    role_gone = ("NoSuchEntity", f"The role with name {role_name} cannot be found.")
    until_raises(lambda: iam.get_role(RoleName=role_name))
    expect_error(lambda: iam.get_role(RoleName=role_name), *role_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
