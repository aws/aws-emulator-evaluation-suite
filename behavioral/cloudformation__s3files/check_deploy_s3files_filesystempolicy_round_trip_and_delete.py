"""deploy-s3files-filesystempolicy-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-s3files-filesystempolicy-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3files"]

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

def _resources(marker: str, bucket: str, versioning: str = "Enabled") -> dict:
    """A versioned bucket, a role S3 Files assumes scoped to that bucket, and a file system."""
    t = [{"Key": "sim2real-s3files", "Value": marker}]
    bucket_arn = {"Fn::GetAtt": ["Bucket", "Arn"]}
    return {
        "Bucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {"BucketName": bucket,
                           "VersioningConfiguration": {"Status": versioning}, "Tags": t},
        },
        "Role": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"Service": "elasticfilesystem.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }],
                },
                "Policies": [{
                    "PolicyName": "allow-own-bucket",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Action": "s3:*",
                            "Resource": [bucket_arn,
                                         {"Fn::Sub": ["${Arn}/*", {"Arn": bucket_arn}]}],
                        }],
                    },
                }],
                "Tags": t,
            },
        },
        "FS": {
            "Type": "AWS::S3Files::FileSystem",
            "Properties": {
                "Bucket": bucket_arn,
                "RoleArn": {"Fn::GetAtt": ["Role", "Arn"]},
                "Tags": t,
            },
        },
    }


_FS_OUTPUTS = {
    "FileSystemRef": {"Value": {"Ref": "FS"}},
    "FileSystemId": {"Value": {"Fn::GetAtt": ["FS", "FileSystemId"]}},
    "BucketArn": {"Value": {"Fn::GetAtt": ["Bucket", "Arn"]}},
    "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
}


def _template(resources: dict, outputs: dict) -> str:
    body = {"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources}
    if outputs:
        body["Outputs"] = outputs
    return json.dumps(body)


def _bucket_name(ctx) -> str:
    return ctx.unique_name("sim2real-s3files-").lower()[:63]


def _listed_fs(s3files, bucket_arn: str) -> list:
    """The file systems S3 Files pages out for ``bucket_arn``."""
    return paginate(s3files, "list_file_systems", "fileSystems", bucket=bucket_arn)


def _policy(principal, resource) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": principal},
            "Action": "s3files:GetFileSystem",
            "Resource": resource,
        }],
    }


def _stack_template(marker: str, bucket: str, with_policy: bool = True) -> str:
    resources = _resources(marker, bucket)
    outputs = dict(_FS_OUTPUTS)
    if with_policy:
        resources["Policy"] = {
            "Type": "AWS::S3Files::FileSystemPolicy",
            "Properties": {
                "FileSystemId": {"Fn::GetAtt": ["FS", "FileSystemId"]},
                "Policy": _policy({"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"},
                                  {"Fn::GetAtt": ["FS", "FileSystemArn"]}),
            },
        }
        outputs["PolicyRef"] = {"Value": {"Ref": "Policy"}}
    return _template(resources, outputs)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::S3Files::FileSystemPolicy reads back through GetFileSystemPolicy as the
    whole declared document; an update dropping it leaves the file system without a policy, and
    deleting the stack removes the file system.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-s3files-filesystempolicy.html
    """
    s3files = ctx.client("s3files")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-s3filespol-")
    bucket = _bucket_name(ctx)

    stack_id = create_stack(ctx, cfn, stack, _stack_template(stack, bucket),
                            Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]

    listed = _listed_fs(s3files, out["BucketArn"])
    assert [f["fileSystemId"] for f in listed] == [out["FileSystemId"]] == [out["PolicyRef"]], (
        f"ListFileSystems for the bucket {listed!r}, GetAtt FileSystemId "
        f"{out['FileSystemId']!r}, Policy Ref {out['PolicyRef']!r}"
    )
    fs_id = listed[0]["fileSystemId"]
    got = s3files.get_file_system_policy(fileSystemId=fs_id)
    want = _policy(f"arn:{partition}:iam::{ctx.account}:root", listed[0]["fileSystemArn"])
    assert (got["fileSystemId"], json.loads(got["policy"])) == (fs_id, want), (
        f"GetFileSystemPolicy {got!r}, expected {want!r}"
    )

    # The policy's own delete: an update dropping it while the file system still answers.
    cfn.update_stack(StackName=stack_id, TemplateBody=_stack_template(stack, bucket, False),
                     Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"policy-removing update ended {status!r}"
    expect_error(lambda: s3files.get_file_system_policy(fileSystemId=fs_id),
                 *("ResourceNotFoundException", "File system policy does not exist."))
    assert s3files.get_file_system(fileSystemId=fs_id)["status"] == "available", (
        "the file system after the policy update is not available"
    )

    delete_stack(cfn, stack_id)
    expect_error(lambda: s3files.get_file_system(fileSystemId=fs_id),
                 *("ResourceNotFoundException", "File system does not exist."))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
