"""update-mount-target-security-groups-persisted."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-mount-target-security-groups-persisted"
GROUP = "state"
SERVICES = ["s3files"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateMountTarget replaces security groups and the change is durably reflected on Get."""
    s3files = ctx.client("s3files")
    ec2 = ctx.client("ec2")
    bucket = _create_versioned_bucket(ctx)
    role_arn = _create_s3files_role(ctx, bucket["name"])
    fs_id = _create_and_wait_available(ctx, bucket["arn"], role_arn)
    net = _create_test_vpc_subnets(ctx, count=1)
    mt_id = _create_mount_target_and_wait_available(ctx, fs_id, net["subnet_ids"][0])

    new_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-s3files-sg-"),
        Description="sim2real s3files behavioral check",
        VpcId=net["vpc_id"],
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-s3files-sg-")}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=new_sg))

    updated = s3files.update_mount_target(mountTargetId=mt_id, securityGroups=[new_sg])
    assert updated["securityGroups"] == [new_sg], f"expected UpdateMountTarget to echo {[new_sg]}, got {updated['securityGroups']}"

    final = _poll_until(
        lambda: s3files.get_mount_target(mountTargetId=mt_id),
        lambda r: r.get("status") in ("available", "error"),
        timeout_s=120.0,
        interval_s=3.0,
    )
    assert final["status"] == "available", f"expected mount target to settle in 'available', got {final['status']!r}"
    assert final["securityGroups"] == [new_sg], f"expected persisted security groups {[new_sg]}, got {final['securityGroups']}"


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _delete_mount_target_and_wait(s3files, mt_id, *, timeout_s=240.0, interval_s=5.0):
    try:
        s3files.delete_mount_target(mountTargetId=mt_id)
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            s3files.get_mount_target(mountTargetId=mt_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)


def _retry_delete(fn, *, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound"):
                return
            if code == "DependencyViolation":
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    if last_err:
        raise last_err


def _create_versioned_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-s3files-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})

    def _cleanup():
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=name):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
            objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])]
            if objs:
                s3.delete_objects(Bucket=name, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return {"name": name, "arn": f"arn:aws:s3:::{name}"}


def _create_s3files_role(ctx, bucket_name):
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-s3files-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowS3FilesAssumeRole",
            "Effect": "Allow",
            "Principal": {"Service": "elasticfilesystem.amazonaws.com"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
        }],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "S3Access",
            "Effect": "Allow",
            "Action": ["s3:ListBucket", "s3:ListBucketVersions", "s3:GetObject*", "s3:PutObject*",
                       "s3:DeleteObject*", "s3:AbortMultipartUpload"],
            "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="s3files-access", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3files-access"))
    return role_arn


def _create_and_wait_available(ctx, bucket_arn, role_arn, **kwargs):
    s3files = ctx.client("s3files")
    deadline = time.monotonic() + 60.0
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = s3files.create_file_system(bucket=bucket_arn, roleArn=role_arn, **kwargs)
            break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ResourceNotFoundException", "ValidationException"):
                last_err = err
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise last_err
    fs_id = resp["fileSystemId"]
    ctx.on_cleanup(lambda: s3files.delete_file_system(fileSystemId=fs_id))
    _poll_until(
        lambda: s3files.get_file_system(fileSystemId=fs_id)["status"],
        lambda s: s == "available",
        timeout_s=300.0,
        interval_s=5.0,
    )
    return fs_id


def _create_test_vpc_subnets(ctx, count=1):
    ec2 = ctx.client("ec2")
    tag_val = ctx.unique_name("sim2real-s3files-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.87.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": tag_val}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    azs = [z["ZoneName"] for z in ec2.describe_availability_zones()["AvailabilityZones"]]
    subnet_ids = []
    for i in range(count):
        az = azs[i % len(azs)]
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.87.{i + 1}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": tag_val}]}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _retry_delete(lambda: ec2.delete_subnet(SubnetId=sid)))
        subnet_ids.append(subnet_id)
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids}


def _create_mount_target_and_wait_available(ctx, fs_id, subnet_id):
    s3files = ctx.client("s3files")
    mt_id = s3files.create_mount_target(fileSystemId=fs_id, subnetId=subnet_id)["mountTargetId"]
    ctx.on_cleanup(lambda: _delete_mount_target_and_wait(s3files, mt_id))
    _poll_until(
        lambda: s3files.get_mount_target(mountTargetId=mt_id)["status"],
        lambda s: s == "available",
        timeout_s=480.0,
        interval_s=10.0,
    )
    return mt_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
