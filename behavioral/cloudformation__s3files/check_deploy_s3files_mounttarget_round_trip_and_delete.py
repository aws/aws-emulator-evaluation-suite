"""deploy-s3files-mounttarget-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-s3files-mounttarget-round-trip-and-delete"
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

_VPC_CIDR = "10.120.0.0/16"
_SUBNET_CIDR = "10.120.0.0/24"


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


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::S3Files::MountTarget is the one S3 Files lists for its file system,
    with the declared file system, subnet, security group and VPC; deleting the stack removes the
    mount target, which S3 Files then reports as absent by id.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-s3files-mounttarget.html
    """
    s3files = ctx.client("s3files")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-s3filesmt-")
    t = [{"Key": "sim2real-s3files", "Value": stack}]
    resources = _resources(stack, _bucket_name(ctx))
    resources.update({
        # A fresh VPC per run: the fixed CIDR never overlaps another run's network.
        "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR, "Tags": t}},
        "Subnet": {
            "Type": "AWS::EC2::Subnet",
            "Properties": {
                "VpcId": {"Ref": "Vpc"},
                "CidrBlock": _SUBNET_CIDR,
                "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]},
                "Tags": t,
            },
        },
        "Sg": {
            "Type": "AWS::EC2::SecurityGroup",
            "Properties": {"GroupDescription": "sim2real s3files mount target",
                           "VpcId": {"Ref": "Vpc"}, "Tags": t},
        },
        "MountTarget": {
            "Type": "AWS::S3Files::MountTarget",
            "Properties": {
                "FileSystemId": {"Fn::GetAtt": ["FS", "FileSystemId"]},
                "SubnetId": {"Ref": "Subnet"},
                "SecurityGroups": [{"Fn::GetAtt": ["Sg", "GroupId"]}],
            },
        },
    })
    outputs = dict(
        _FS_OUTPUTS,
        MountTargetRef={"Value": {"Ref": "MountTarget"}},
        NetworkInterfaceId={"Value": {"Fn::GetAtt": ["MountTarget", "NetworkInterfaceId"]}},
        VpcIdAtt={"Value": {"Fn::GetAtt": ["MountTarget", "VpcId"]}},
        MountTargetStatus={"Value": {"Fn::GetAtt": ["MountTarget", "Status"]}},
        SubnetId={"Value": {"Ref": "Subnet"}},
        SgId={"Value": {"Fn::GetAtt": ["Sg", "GroupId"]}},
        VpcId={"Value": {"Ref": "Vpc"}},
    )

    stack_id = create_stack(ctx, cfn, stack, _template(resources, outputs),
                            Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)

    # Ref against the file system's paged ListMountTargets, never a read keyed by the Ref.
    listed = paginate(s3files, "list_mount_targets", "mountTargets",
                      fileSystemId=out["FileSystemId"])
    assert [m["mountTargetId"] for m in listed] == [out["MountTargetRef"]], (
        f"ListMountTargets of the file system {listed!r}, Ref {out['MountTargetRef']!r}"
    )
    mt = s3files.get_mount_target(mountTargetId=listed[0]["mountTargetId"])
    got = (mt["fileSystemId"], mt["networkInterfaceId"], mt["vpcId"], out["VpcIdAtt"],
           mt["status"], out["MountTargetStatus"], mt["subnetId"], mt["securityGroups"])
    want = (out["FileSystemId"], out["NetworkInterfaceId"], out["VpcId"], out["VpcId"],
            "available", "available", out["SubnetId"], [out["SgId"]])
    assert got == want, f"mount target reads {got!r}, expected {want!r}"

    delete_stack(cfn, stack_id)
    expect_error(lambda: s3files.get_mount_target(mountTargetId=mt["mountTargetId"]),
                 *("ResourceNotFoundException", "Mount target does not exist."))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
