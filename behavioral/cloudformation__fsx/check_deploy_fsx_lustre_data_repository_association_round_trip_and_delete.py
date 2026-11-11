"""deploy-fsx-lustre-data-repository-association-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-fsx-lustre-data-repository-association-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "fsx"]

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

_VPC_CIDR = "10.124.0.0/16"
_SUBNET_CIDR = "10.124.1.0/24"
_STORAGE_CAPACITY = 1200
_FS_PATH = "/data"
# A Lustre file system takes most of the run to create; its own wait gets this long.
_FS_WAIT_S = 1500.0


def _template(tag_value: str, az: str, *, with_dra: bool = True) -> str:
    t = [{"Key": "sim2real-fsx", "Value": tag_value}]
    resources = {
        "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR, "Tags": t}},
        "Subnet": {
            "Type": "AWS::EC2::Subnet",
            "Properties": {"VpcId": {"Ref": "Vpc"}, "CidrBlock": _SUBNET_CIDR,
                           "AvailabilityZone": az, "Tags": t},
        },
        "Sg": {
            "Type": "AWS::EC2::SecurityGroup",
            "Properties": {
                "GroupDescription": "fsx lustre client access",
                "VpcId": {"Ref": "Vpc"},
                "SecurityGroupIngress": [
                    {"IpProtocol": "tcp", "FromPort": 988, "ToPort": 988, "CidrIp": _VPC_CIDR},
                    {"IpProtocol": "tcp", "FromPort": 1021, "ToPort": 1023,
                     "CidrIp": _VPC_CIDR},
                ],
                "Tags": t,
            },
        },
        "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"Tags": t}},
        "FileSystem": {
            "Type": "AWS::FSx::FileSystem",
            "Properties": {
                "FileSystemType": "LUSTRE",
                "FileSystemTypeVersion": "2.12",
                "StorageCapacity": _STORAGE_CAPACITY,
                "SubnetIds": [{"Ref": "Subnet"}],
                "SecurityGroupIds": [{"Ref": "Sg"}],
                "LustreConfiguration": {
                    "DeploymentType": "PERSISTENT_2",
                    "PerUnitStorageThroughput": 125,
                    "DataCompressionType": "NONE",
                },
                "Tags": t,
            },
        },
    }
    outputs = {
        "BucketName": {"Value": {"Ref": "Bucket"}},
        "SubnetId": {"Value": {"Ref": "Subnet"}},
        "FileSystemId": {"Value": {"Ref": "FileSystem"}},
    }
    if with_dra:
        resources["Dra"] = {
            "Type": "AWS::FSx::DataRepositoryAssociation",
            "Properties": {
                "FileSystemId": {"Ref": "FileSystem"},
                "FileSystemPath": _FS_PATH,
                "DataRepositoryPath": {"Fn::Join": ["", ["s3://", {"Ref": "Bucket"}, "/export/"]]},
                "BatchImportMetaDataOnCreate": False,
                "Tags": t,
            },
        }
        outputs["AssociationId"] = {"Value": {"Ref": "Dra"}}
        outputs["AssociationArn"] = {"Value": {"Fn::GetAtt": "Dra.ResourceARN"}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": outputs,
    })


def _own_tags(tag_list) -> dict:
    """The resource's tags without the propagated stack tag and the aws: system tags."""
    return {t["Key"]: t["Value"] for t in tag_list
            if t["Key"] != "sim2real" and not t["Key"].startswith("aws:")}


def _associations(fsx, fs_id: str) -> list[dict]:
    """Every page of the file system's data repository associations (the op has no paginator)."""
    kw = {"Filters": [{"Name": "file-system-id", "Values": [fs_id]}]}
    out = []
    while True:
        page = fsx.describe_data_repository_associations(**kw)
        out += page["Associations"]
        if not page.get("NextToken"):
            return out
        kw["NextToken"] = page["NextToken"]


def _usable_az(ec2) -> str:
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert usable, "no available Availability Zone in this region"
    return usable[0]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::FSx::DataRepositoryAssociation on a Lustre file system reads back.

    Refs and GetAtt match FSx's listings and every property reads back; dropping the association
    removes it while the file system answers, and the stack delete removes the file system.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-fsx-datarepositoryassociation.html
    """
    ec2 = ctx.client("ec2")
    fsx = ctx.client("fsx")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-fsxdra-")
    az = _usable_az(ec2)

    stack_id = create_stack(ctx, cfn, stack, _template(stack, az))
    status = wait_stack(cfn, stack_id, timeout_s=_FS_WAIT_S)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    bucket = outputs["BucketName"]

    # Ref against an independent read: the account's file systems, every page, by the run tag.
    own = [f for f in paginate(fsx, "describe_file_systems", "FileSystems")
           if _own_tags(f.get("Tags", [])) == {"sim2real-fsx": stack}]
    assert [f["FileSystemId"] for f in own] == [outputs["FileSystemId"]], (
        f"FSx lists {[f['FileSystemId'] for f in own]!r}; Ref is {outputs['FileSystemId']!r}"
    )
    fs = own[0]
    fs_id = fs["FileSystemId"]
    lustre = fs["LustreConfiguration"]
    got = (fs["Lifecycle"], fs["FileSystemTypeVersion"], fs["StorageCapacity"], fs["SubnetIds"],
           lustre["DeploymentType"], lustre["PerUnitStorageThroughput"],
           lustre["DataCompressionType"])
    want = ("AVAILABLE", "2.12", _STORAGE_CAPACITY, [outputs["SubnetId"]], "PERSISTENT_2", 125,
            "NONE")
    assert got == want, f"file system reads {got!r}, expected {want!r}"

    assocs = _associations(fsx, fs_id)
    assert [(a["AssociationId"], a["ResourceARN"]) for a in assocs] == [
        (outputs["AssociationId"], outputs["AssociationArn"])
    ], f"FSx lists {assocs!r} for {fs_id!r}"
    a = assocs[0]
    got = (a["Lifecycle"], a["FileSystemPath"], a["DataRepositoryPath"],
           a["BatchImportMetaDataOnCreate"], _own_tags(a.get("Tags", [])))
    want = ("AVAILABLE", _FS_PATH, f"s3://{bucket}/export/", False, {"sim2real-fsx": stack})
    assert got == want, f"association reads {got!r}, expected {want!r}"

    # Child before parent: an update drops only the association; the same file system answers.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(stack, az, with_dra=False))
    status = wait_stack(cfn, stack_id, timeout_s=_FS_WAIT_S)
    assert status == "UPDATE_COMPLETE", f"association-removing update ended {status!r}"
    left = _associations(fsx, fs_id)
    assert left == [], f"after dropping the association FSx still lists {left!r}"
    after = fsx.describe_file_systems(FileSystemIds=[fs_id])["FileSystems"]
    assert [(f["CreationTime"], f["Lifecycle"]) for f in after] == [
        (fs["CreationTime"], "AVAILABLE")
    ], f"after the update the file system reads {after!r}"

    delete_stack(cfn, stack_id)
    gone = ("FileSystemNotFound", f"File system '{fs_id}' does not exist.")
    expect_error(lambda: fsx.describe_file_systems(FileSystemIds=[fs_id]), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
