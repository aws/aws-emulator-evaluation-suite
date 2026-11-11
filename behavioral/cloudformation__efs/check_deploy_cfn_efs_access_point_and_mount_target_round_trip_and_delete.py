"""deploy-cfn-efs-access-point-and-mount-target-round-trip-and-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-efs-access-point-and-mount-target-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "efs"]

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


_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.84.0.0/16
  Subnet:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.84.1.0/24
  Sg:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: sim2real efs access point and mount target check
      VpcId: !Ref Vpc
  Fs:
    Type: AWS::EFS::FileSystem
    Properties:
      Encrypted: true
  Ap:
    Type: AWS::EFS::AccessPoint
    Properties:
      FileSystemId: !Ref Fs
      PosixUser:
        Uid: "1500"
        Gid: "1500"
      RootDirectory:
        Path: /sim2real-ap
        CreationInfo:
          OwnerUid: "1500"
          OwnerGid: "1500"
          Permissions: "0750"
  Mt:
    Type: AWS::EFS::MountTarget
    Properties:
      FileSystemId: !Ref Fs
      SubnetId: !Ref Subnet
      SecurityGroups:
        - !Ref Sg
Outputs:
  FsIdRef:
    Value: !Ref Fs
  SubnetIdRef:
    Value: !Ref Subnet
  SgIdRef:
    Value: !Ref Sg
  ApIdRef:
    Value: !Ref Ap
  ApArnGetAtt:
    Value: !GetAtt Ap.Arn
  MtIdRef:
    Value: !Ref Mt
  MtIpGetAtt:
    Value: !GetAtt Mt.IpAddress
"""


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::EFS::AccessPoint and AWS::EFS::MountTarget reach CREATE_COMPLETE,
    EFS reflects every property and GetAtt attribute, and deleting the stack removes both.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-efs-accesspoint.html
    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-efs-mounttarget.html
    """
    cfn = ctx.client("cloudformation")
    efs = ctx.client("efs")

    stack = ctx.unique_name("sim2real-behav-stack-")

    stack_id = create_stack(ctx, cfn, stack, _TEMPLATE)
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    fs_id = outputs["FsIdRef"]
    subnet_id = outputs["SubnetIdRef"]
    sg_id = outputs["SgIdRef"]
    ap_id = outputs["ApIdRef"]
    mt_id = outputs["MtIdRef"]

    fss = efs.describe_file_systems(FileSystemId=fs_id)["FileSystems"]
    assert [(f["FileSystemId"], f["Encrypted"]) for f in fss] == [(fs_id, True)], f"file system {fss!r}"

    # Refs against independent reads: the file system's access points and mount targets.
    aps = paginate(efs, "describe_access_points", "AccessPoints", FileSystemId=fs_id)
    assert [a["AccessPointId"] for a in aps] == [ap_id], f"access points of {fs_id!r}: {aps!r}"
    ap = aps[0]
    assert ap["FileSystemId"] == fs_id, f"access point FileSystemId {ap['FileSystemId']!r}"
    assert ap["AccessPointId"] == ap_id, (
        f"expected Ref Ap to equal AccessPointId, got {ap['AccessPointId']!r} vs {ap_id!r}"
    )
    assert ap["AccessPointArn"] == outputs["ApArnGetAtt"], (
        f"expected Fn::GetAtt Ap.Arn to match DescribeAccessPoints AccessPointArn "
        f"{ap['AccessPointArn']!r}, got {outputs['ApArnGetAtt']!r}"
    )
    assert ap["PosixUser"] == {"Uid": 1500, "Gid": 1500, "SecondaryGids": []}, (
        f"expected PosixUser {{'Uid': 1500, 'Gid': 1500, 'SecondaryGids': []}}, got {ap['PosixUser']!r}"
    )
    assert ap["RootDirectory"] == {
        "Path": "/sim2real-ap",
        "CreationInfo": {"OwnerUid": 1500, "OwnerGid": 1500, "Permissions": "0750"},
    }, f"expected the template's RootDirectory, got {ap['RootDirectory']!r}"

    mts = paginate(efs, "describe_mount_targets", "MountTargets", FileSystemId=fs_id)
    assert [m["MountTargetId"] for m in mts] == [mt_id], f"mount targets of {fs_id!r}: {mts!r}"
    mt = mts[0]
    assert mt["FileSystemId"] == fs_id, f"mount target FileSystemId {mt['FileSystemId']!r}"
    assert mt["MountTargetId"] == mt_id, (
        f"expected Ref Mt to equal MountTargetId, got {mt['MountTargetId']!r} vs {mt_id!r}"
    )
    assert mt["SubnetId"] == subnet_id, (
        f"expected the mount target's SubnetId to be {subnet_id!r}, EFS reports {mt['SubnetId']!r}"
    )
    assert mt["IpAddress"] == outputs["MtIpGetAtt"], (
        f"expected Fn::GetAtt Mt.IpAddress to match DescribeMountTargets IpAddress "
        f"{mt['IpAddress']!r}, got {outputs['MtIpGetAtt']!r}"
    )

    mt_sgs = efs.describe_mount_target_security_groups(MountTargetId=mt_id)["SecurityGroups"]
    assert mt_sgs == [sg_id], (
        f"expected the mount target's security groups to be [{sg_id!r}], EFS reports {mt_sgs!r}"
    )

    delete_stack(cfn, stack_id)
    expect_error(lambda: efs.describe_access_points(AccessPointId=ap_id),
                 *("AccessPointNotFound", f"Access point '{ap_id}' does not exist."))
    expect_error(lambda: efs.describe_mount_targets(MountTargetId=mt_id),
                 *("MountTargetNotFound", f"Mount target '{mt_id}' does not exist."))
    expect_error(lambda: efs.describe_file_systems(FileSystemId=fs_id),
                 *("FileSystemNotFound", f"File system '{fs_id}' does not exist."))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
