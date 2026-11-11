"""create-location-efs-tag-mutations-are-visible-via-list-tags."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-location-efs-tag-mutations-are-visible-via-list-tags"
GROUP = "tag-lifecycle"
SERVICES = ["datasync"]


@tags("axis:happy-path", "concern:representation", "cap:c1", "plane:control")
def run(ctx) -> None:
    """An EFS location's tags evolve through TagResource/UntagResource, and ListTagsForResource
    always reflects the net effect of every call so far, not just the most recent one.
    """
    efs = ctx.client("efs")
    ec2 = ctx.client("ec2")
    ds = ctx.client("datasync")

    vpc_id = ec2.create_vpc(CidrBlock="10.90.0.0/24")["Vpc"]["VpcId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound"))

    az = _usable_az(ec2)
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.90.0.0/25", AvailabilityZone=az
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_subnet(SubnetId=subnet_id), "InvalidSubnetID.NotFound"))

    sg_name = ctx.unique_name("sim2real-behav-dsefs-sg-")
    sg_id = ec2.create_security_group(
        VpcId=vpc_id, GroupName=sg_name, Description="sim2real datasync efs check",
        TagSpecifications=[{"ResourceType": "security-group",
                             "Tags": [{"Key": "sim2real", "Value": sg_name}]}],
    )["GroupId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_security_group(GroupId=sg_id), "InvalidGroup.NotFound"))

    token = ctx.unique_name("sim2real-behav-dsefs-")
    fs_id = efs.create_file_system(
        CreationToken=token, Encrypted=False,
        Tags=[{"Key": "sim2real", "Value": token}],
    )["FileSystemId"]
    ctx.on_cleanup(_teardown(lambda: efs.delete_file_system(FileSystemId=fs_id), "FileSystemNotFound"))
    _wait_for(lambda: efs.describe_file_systems(FileSystemId=fs_id)["FileSystems"][0]["LifeCycleState"],
              "available", what=f"EFS filesystem {fs_id}")

    mt_id = efs.create_mount_target(
        FileSystemId=fs_id, SubnetId=subnet_id, SecurityGroups=[sg_id]
    )["MountTargetId"]
    ctx.on_cleanup(lambda: _delete_mount_target_and_wait(efs, mt_id))
    _wait_for(lambda: efs.describe_mount_targets(MountTargetId=mt_id)["MountTargets"][0]["LifeCycleState"],
              "available", what=f"EFS mount target {mt_id}", budget_s=180.0)

    fs_arn = f"arn:aws:elasticfilesystem:{ctx.region}:{ctx.account}:file-system/{fs_id}"
    subnet_arn = f"arn:aws:ec2:{ctx.region}:{ctx.account}:subnet/{subnet_id}"
    sg_arn = f"arn:aws:ec2:{ctx.region}:{ctx.account}:security-group/{sg_id}"

    loc_arn = ds.create_location_efs(
        EfsFilesystemArn=fs_arn,
        Ec2Config={"SubnetArn": subnet_arn, "SecurityGroupArns": [sg_arn]},
        Tags=[{"Key": "sim2real", "Value": token}, {"Key": "stage", "Value": "dev"}],
    )["LocationArn"]
    ctx.on_cleanup(_teardown(lambda: ds.delete_location(LocationArn=loc_arn), "InvalidRequestException"))

    initial = _tag_map(ds, loc_arn)
    assert initial == {"sim2real": token, "stage": "dev"}, (
        f"tags right after create are {initial!r}, expected sim2real+stage"
    )

    ds.tag_resource(ResourceArn=loc_arn, Tags=[{"Key": "owner", "Value": "sim2real-check"}])
    after_add = _tag_map(ds, loc_arn)
    assert after_add == {"sim2real": token, "stage": "dev", "owner": "sim2real-check"}, (
        f"tags after adding 'owner' are {after_add!r}, expected the original two plus 'owner'"
    )

    ds.untag_resource(ResourceArn=loc_arn, Keys=["stage"])
    after_remove = _tag_map(ds, loc_arn)
    assert after_remove == {"sim2real": token, "owner": "sim2real-check"}, (
        f"tags after removing 'stage' are {after_remove!r}, expected 'sim2real' and 'owner' only"
    )



def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _delete_mount_target_and_wait(efs, mt_id: str, *, budget_s: float = 180.0, poll_s: float = 5.0) -> None:
    """Delete the mount target and wait for its ENI to clear before the filesystem's own delete runs.

    DeleteMountTarget is asynchronous, so a following DeleteFileSystem races it and fails
    FileSystemInUse if nothing waits here.
    """
    try:
        efs.delete_mount_target(MountTargetId=mt_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "MountTargetNotFound":
            raise
        return
    deadline = time.monotonic() + budget_s
    while True:
        try:
            efs.describe_mount_targets(MountTargetId=mt_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "MountTargetNotFound":
                return
            raise
        if time.monotonic() > deadline:
            raise AssertionError(f"mount target {mt_id} still present {budget_s}s after delete")
        time.sleep(poll_s)


def _usable_az(ec2) -> str:
    zones = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    assert zones, "no available availability zone in this region"
    return sorted(z["ZoneName"] for z in zones)[0]


def _wait_for(observe, terminal: str, *, what: str, budget_s: float = 60.0, poll_s: float = 3.0) -> None:
    deadline = time.monotonic() + budget_s
    state = observe()
    while state != terminal:
        if time.monotonic() > deadline:
            raise AssertionError(f"{what} never reached {terminal!r} within {budget_s}s; last state {state!r}")
        time.sleep(poll_s)
        state = observe()


def _tag_map(ds, resource_arn: str) -> dict:
    tags_out = {}
    for page in ds.get_paginator("list_tags_for_resource").paginate(ResourceArn=resource_arn):
        for t in page.get("Tags", []):
            tags_out[t["Key"]] = t["Value"]
    return tags_out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
