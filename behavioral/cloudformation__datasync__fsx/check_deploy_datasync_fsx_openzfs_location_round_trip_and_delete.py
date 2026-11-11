"""deploy-datasync-fsx-openzfs-location-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-datasync-fsx-openzfs-location-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "datasync", "fsx"]

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


_VPC_CIDR = "10.142.0.0/16"
_SUBNET_CIDR = "10.142.1.0/24"
_OPENZFS_STORAGE_GIB = 64
_OPENZFS_THROUGHPUT_MBPS = 64
_NFS_VERSION = "NFS3"
# FSx for OpenZFS over NFS needs 111, 2049 and 20001-20003, TCP and UDP, self-referencing
# (Amazon FSx for OpenZFS VPC access-control guide).
_SELF_REF_RULES = [
    ("tcp", 111, 111), ("udp", 111, 111), ("tcp", 2049, 2049), ("udp", 2049, 2049),
    ("tcp", 20001, 20003), ("udp", 20001, 20003),
]
_CREATE_TIMEOUT_S = 1500.0


def _template(fs_tag: str, with_location: bool = True) -> str:
    t = [{"Key": "sim2real-fs", "Value": fs_tag}]
    resources: dict = {
        "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR}},
        "Subnet": {
            "Type": "AWS::EC2::Subnet",
            "Properties": {
                "VpcId": {"Ref": "Vpc"}, "CidrBlock": _SUBNET_CIDR,
                "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]},
            },
        },
        "Sg": {
            "Type": "AWS::EC2::SecurityGroup",
            "Properties": {
                "GroupDescription": "sim2real fsx-openzfs access", "VpcId": {"Ref": "Vpc"},
            },
        },
        "Fs": {
            "Type": "AWS::FSx::FileSystem",
            "Properties": {
                "FileSystemType": "OPENZFS",
                "StorageCapacity": _OPENZFS_STORAGE_GIB,
                "SubnetIds": [{"Ref": "Subnet"}],
                "SecurityGroupIds": [{"Ref": "Sg"}],
                "OpenZFSConfiguration": {
                    "DeploymentType": "SINGLE_AZ_1",
                    "ThroughputCapacity": _OPENZFS_THROUGHPUT_MBPS,
                },
                "Tags": t,
            },
        },
        "Location": {
            "Type": "AWS::DataSync::LocationFSxOpenZFS",
            "Properties": {
                "FsxFilesystemArn": {"Fn::GetAtt": ["Fs", "ResourceARN"]},
                "SecurityGroupArns": [{
                    "Fn::Sub": "arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:"
                               "security-group/${Sg}"
                }],
                "Protocol": {"NFS": {"MountOptions": {"Version": _NFS_VERSION}}},
                "Tags": t,
            },
        },
    }
    for i, (proto, lo, hi) in enumerate(_SELF_REF_RULES):
        resources[f"Ingress{i}"] = {
            "Type": "AWS::EC2::SecurityGroupIngress",
            "Properties": {
                "GroupId": {"Fn::GetAtt": ["Sg", "GroupId"]},
                "SourceSecurityGroupId": {"Fn::GetAtt": ["Sg", "GroupId"]},
                "IpProtocol": proto, "FromPort": lo, "ToPort": hi,
            },
        }
    resources["Fs"]["DependsOn"] = [f"Ingress{i}" for i in range(len(_SELF_REF_RULES))]
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": {
            "SubnetId": {"Value": {"Ref": "Subnet"}},
            "SgId": {"Value": {"Fn::GetAtt": ["Sg", "GroupId"]}},
            "FsId": {"Value": {"Ref": "Fs"}},
            "FsArn": {"Value": {"Fn::GetAtt": ["Fs", "ResourceARN"]}},
            "RootVolumeId": {"Value": {"Fn::GetAtt": ["Fs", "RootVolumeId"]}},
            "LocationRef": {"Value": {"Ref": "Location"}},
            "LocationArn": {"Value": {"Fn::GetAtt": ["Location", "LocationArn"]}},
            "LocationUri": {"Value": {"Fn::GetAtt": ["Location", "LocationUri"]}},
        },
    }
    if not with_location:
        del template["Resources"]["Location"]
        for key in ("LocationRef", "LocationArn", "LocationUri"):
            del template["Outputs"][key]
    return json.dumps(template)


def _user_tags(tag_list) -> dict:
    return {t["Key"]: t["Value"] for t in tag_list if not t["Key"].startswith("aws:")}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation FSx for OpenZFS file system and DataSync LocationFSxOpenZFS read back.

    Every templated property, Ref, GetAtt and tag reads back; dropping the location removes it
    while the same file system answers, then the stack delete removes the file system.
    """
    fsx = ctx.client("fsx")
    ds = ctx.client("datasync")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-dsfsxz-")
    fs_tag = ctx.unique_name("sim2real-dsfsxz-fs-")

    stack_id = create_stack(ctx, cfn, stack, _template(fs_tag))
    status = wait_stack(cfn, stack_id, timeout_s=_CREATE_TIMEOUT_S)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]
    fs_id, fs_arn, loc_ref = out["FsId"], out["FsArn"], out["LocationRef"]
    want_sg_arn = f"arn:{partition}:ec2:{ctx.region}:{ctx.account}:security-group/{out['SgId']}"
    want_tags = {"sim2real": stack, "sim2real-fs": fs_tag}

    # FSx: the file system reads back as declared, its Ref and both GetAtts included.
    listed = [f for f in paginate(fsx, "describe_file_systems", "FileSystems")
              if f["FileSystemId"] == fs_id]
    assert len(listed) == 1, f"DescribeFileSystems lists {len(listed)} entries for {fs_id!r}"
    fs = listed[0]
    zfs = fs["OpenZFSConfiguration"]
    got = (fs["ResourceARN"], fs["FileSystemType"], fs["StorageCapacity"], zfs["DeploymentType"],
           zfs["ThroughputCapacity"], zfs["RootVolumeId"], fs["SubnetIds"], fs["Lifecycle"])
    want = (fs_arn, "OPENZFS", _OPENZFS_STORAGE_GIB, "SINGLE_AZ_1", _OPENZFS_THROUGHPUT_MBPS,
            out["RootVolumeId"], [out["SubnetId"]], "AVAILABLE")
    assert got == want, f"OpenZFS file system reads {got!r}, expected {want!r}"
    assert _user_tags(fs["Tags"]) == want_tags, f"OpenZFS FS tags {fs['Tags']!r}"

    # DataSync: Ref == the location ListLocations finds by the GetAtt LocationUri.
    uri = out["LocationUri"]
    found = [loc["LocationArn"] for loc in paginate(
        ds, "list_locations", "Locations",
        Filters=[{"Name": "LocationUri", "Values": [uri], "Operator": "Equals"}],
    )]
    assert found == [loc_ref], f"ListLocations for {uri!r} found {found!r}, Ref {loc_ref!r}"
    assert out["LocationArn"] == loc_ref, f"GetAtt LocationArn {out['LocationArn']!r} != Ref"
    loc = ds.describe_location_fsx_open_zfs(LocationArn=loc_ref)
    got = (loc["LocationArn"], loc["LocationUri"], loc["SecurityGroupArns"],
           loc["Protocol"]["NFS"]["MountOptions"]["Version"])
    assert got == (loc_ref, uri, [want_sg_arn], _NFS_VERSION), f"OpenZFS location reads {got!r}"
    loc_tags = paginate(ds, "list_tags_for_resource", "Tags", ResourceArn=loc_ref)
    assert _user_tags(loc_tags) == want_tags, f"OpenZFS location tags {loc_tags!r}"

    # Child first: the update drops only the location; its own NotFound while the same file
    # system (CreationTime) still answers.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(fs_tag, with_location=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"location-dropping update ended {status!r}"
    location_fsx_open_zfs_gone = ("InvalidRequestException", f"Location {loc_ref} is not found.")
    expect_error(lambda: ds.describe_location_fsx_open_zfs(LocationArn=loc_ref),
                 *location_fsx_open_zfs_gone)
    kept = fsx.describe_file_systems(FileSystemIds=[fs_id])["FileSystems"]
    assert [f["CreationTime"] for f in kept] == [fs["CreationTime"]], (
        f"file system after the update {kept!r}, created {fs['CreationTime']!r}"
    )

    delete_stack(cfn, stack_id)
    file_systems_gone = ("FileSystemNotFound", f"File system '{fs_id}' does not exist.")
    expect_error(lambda: fsx.describe_file_systems(FileSystemIds=[fs_id]), *file_systems_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
