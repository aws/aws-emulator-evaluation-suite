"""native-nfs-mount-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "native-nfs-mount-round-trip"
GROUP = "native-protocol"
SERVICES = ["s3files"]

# Prefix for a data-plane failure: the NFS mount/write/read failed although the mount target
# reported "available". The instance shares the mount target's subnet, which rules out a
# network-reachability cause.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:native", "plane:data")
def run(ctx) -> None:
    """A file written over the S3 Files NFS mount from an EC2 instance in the mount target's subnet
    reads back byte-for-byte, and the write lands in the backing S3 bucket."""
    s3files = ctx.client("s3files")
    s3 = ctx.client("s3")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")
    sts = ctx.client("sts")

    bucket = _create_versioned_bucket(ctx)
    role_arn = _create_s3files_role(ctx, bucket["name"])
    fs_id, fs_arn = _create_and_wait_available(ctx, bucket["arn"], role_arn)
    _grant_nfs_client_access(s3files, fs_id, sts.get_caller_identity()["Account"])

    subnet = _pick_subnet(ec2, ctx=ctx)

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-s3files-sg-"),
        Description="sim2real S3 Files NFS round-trip test",
        VpcId=subnet["VpcId"],
    )["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 2049, "ToPort": 2049, "UserIdGroupPairs": [{"GroupId": sg_id}]}
        ],
    )
    ctx.on_cleanup(lambda: _delete_sg_best_effort(ec2, sg_id))

    mt = _create_mount_target_and_wait_available(ctx, fs_id, subnet["SubnetId"], sg_id)
    assert mt["status"] == "available", f"mount target failed to become available: {mt}"
    mount_ip = mt["ipv4Address"]

    instance_role_name = _create_instance_role(ctx, fs_arn)
    ami_id = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")[
        "Parameter"
    ]["Value"]
    instance_id = _launch_instance(ctx, ec2, ami_id, subnet["SubnetId"], sg_id, instance_role_name)
    ctx.on_cleanup(lambda: _terminate_instance_best_effort(ec2, instance_id))

    ec2.get_waiter("instance_running").wait(
        InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    _wait_ssm_online(ssm, instance_id, timeout_s=300.0)

    payload = f"sim2real-s3files-{ctx.unique_name('payload-')}"
    mount_point = "/mnt/sim2real-s3files-test"
    # S3 Files mounts only through its mount helper (amazon-efs-utils >= 3.0, `mount -t s3files`),
    # which authenticates the NFS session with the instance role over TLS; a plain `mount -t
    # nfs4` has no IAM identity and is refused ("access denied by server").
    script = (
        f"set -e\n"
        f"sudo dnf install -y amazon-efs-utils\n"
        f"sudo mkdir -p {mount_point}\n"
        f"sudo mount -t s3files {fs_id}:/ {mount_point}\n"
        f"echo -n '{payload}' | sudo tee {mount_point}/sim2real-roundtrip.txt\n"
        f"cat {mount_point}/sim2real-roundtrip.txt\n"
        f"sudo umount {mount_point}\n"
    )

    command_id = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": [script]},
        TimeoutSeconds=600,
    )["Command"]["CommandId"]

    invocation = _wait_ssm_command(ssm, command_id, instance_id, timeout_s=660.0)
    assert invocation["Status"] == "Success", (
        f"{DATAPLANE_MARKER}: NFS mount/write/read script against mount target {mt['mountTargetId']} "
        f"({mount_ip}) failed: {invocation.get('StandardErrorContent')}"
    )
    assert payload in invocation["StandardOutputContent"], (
        f"expected payload {payload!r} read back over NFS, got: {invocation['StandardOutputContent']!r}"
    )

    # The write must actually have landed in the backing S3 bucket (S3 Files' whole reason for existing).
    # S3 Files exports a write to the bucket asynchronously, so the object is polled for.
    body = _poll_until(
        lambda: _object_body_or_none(s3, bucket["name"], "sim2real-roundtrip.txt"),
        lambda b: b is not None,
        timeout_s=600.0,
        interval_s=15.0,
    )
    assert body == payload, "backing S3 object does not reflect the NFS write"


# ===== helpers =====

def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


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
    fs_arn = resp["fileSystemArn"]
    ctx.on_cleanup(lambda: _delete_file_system_and_wait(s3files, fs_id))
    _poll_until(
        lambda: s3files.get_file_system(fileSystemId=fs_id)["status"],
        lambda s: s == "available",
        timeout_s=300.0,
        interval_s=5.0,
    )
    return fs_id, fs_arn


def _object_body_or_none(s3, bucket, key):
    try:
        return s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode()
    except ClientError as err:
        if err.response["Error"]["Code"] in ("NoSuchKey", "404"):
            return None
        raise


def _delete_file_system_and_wait(s3files, fs_id, timeout_s=300.0):
    """Delete the file system and wait until it is gone: the bucket refuses DeleteBucket while a
    file system is still attached (BucketHasS3FileSystemAttached)."""
    try:
        s3files.delete_file_system(fileSystemId=fs_id, forceDelete=True)
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            s3files.get_file_system(fileSystemId=fs_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(10)
    raise AssertionError(f"S3 file system {fs_id} still exists {timeout_s}s after DeleteFileSystem")


def _grant_nfs_client_access(s3files, fs_id, account_id):
    """A file system with no policy denies every NFS mount ("access denied by server") -- unlike
    EFS, whose default with no policy is permissive."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowAccountNfsClientAccess",
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "s3files:*",
            "Resource": "*",
        }],
    }
    s3files.put_file_system_policy(fileSystemId=fs_id, policy=json.dumps(policy))


def _pick_subnet(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "map-public-ip-on-launch", "Values": ["true"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError(f"VPC {vpc_id} has no subnets to run the NFS round-trip test")
    return subnets[0]


def _create_mount_target_and_wait_available(ctx, fs_id, subnet_id, sg_id):
    s3files = ctx.client("s3files")
    mt_id = s3files.create_mount_target(
        fileSystemId=fs_id, subnetId=subnet_id, securityGroups=[sg_id]
    )["mountTargetId"]
    ctx.on_cleanup(lambda: _delete_mount_target_and_wait(s3files, mt_id))
    return _poll_until(
        lambda: s3files.get_mount_target(mountTargetId=mt_id),
        lambda r: r.get("status") in ("available", "error"),
        timeout_s=480.0,
        interval_s=5.0,
    )


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


def _create_instance_role(ctx, fs_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-s3files-nfs-role-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }),
    )
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    )
    # A file system with no policy denies every NFS mount ("access denied by server"); grant the
    # instance's own identity the s3files NFS client actions too (belt-and-suspenders alongside
    # the file system's resource policy -- IAM does not validate action names on an identity
    # policy the way it does on a resource policy, so this is cheap insurance).
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="s3files-nfs-client-access",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "AllowS3FilesNfsClientAccess",
                "Effect": "Allow",
                "Action": [
                    "s3files:ClientMount",
                    "s3files:ClientWrite",
                    "s3files:ClientRootAccess",
                ],
                "Resource": fs_arn,
            }],
        }),
    )
    iam.create_instance_profile(InstanceProfileName=role_name)
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(lambda: _delete_instance_role_best_effort(iam, role_name))
    return role_name


def _launch_instance(ctx, ec2, ami_id, subnet_id, sg_id, role_name):
    deadline = time.monotonic() + 60.0
    last_error = None
    while time.monotonic() < deadline:
        try:
            resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                SubnetId=subnet_id,
                SecurityGroupIds=[sg_id],
                IamInstanceProfile={"Name": role_name},
                TagSpecifications=[{
                    "ResourceType": "instance",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-s3files-nfs-")}],
                }],
            )
            return resp["Instances"][0]["InstanceId"]
        except ClientError as e:
            last_error = e
            if e.response["Error"]["Code"] in ("InvalidParameterValue", "Invalid"):
                time.sleep(5.0)
                continue
            raise
    raise AssertionError(f"could not launch EC2 instance (IAM propagation?): {last_error}")


def _wait_ssm_online(ssm, instance_id, timeout_s=300.0):
    def probe():
        info = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )["InstanceInformationList"]
        return info[0]["PingStatus"] if info else None

    return _poll_until(probe, lambda s: s == "Online", timeout_s=timeout_s, interval_s=10.0)


def _wait_ssm_command(ssm, command_id, instance_id, timeout_s=240.0):
    terminal = {"Success", "Failed", "Cancelled", "TimedOut"}

    def probe():
        # SSM's own invocation record propagates asynchronously after SendCommand -- a poll that
        # lands before it exists yet is expected, not a defect, and must retry rather than raise.
        try:
            return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "InvocationDoesNotExist":
                return {"Status": "Pending"}
            raise

    return _poll_until(probe, lambda inv: inv["Status"] in terminal, timeout_s=timeout_s, interval_s=5.0)


def _terminate_instance_best_effort(ec2, instance_id):
    """Terminate the instance and wait until it is gone; only an absent instance is fine."""
    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
    except ClientError as err:
        if err.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
            return
        raise
    ec2.get_waiter("instance_terminated").wait(
        InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


def _delete_instance_role_best_effort(iam, role_name):
    """Unlink, detach, drop the inline policy and delete; only an absent entity is fine."""
    steps = (
        lambda: iam.remove_role_from_instance_profile(InstanceProfileName=role_name, RoleName=role_name),
        lambda: iam.delete_instance_profile(InstanceProfileName=role_name),
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
        ),
        lambda: [
            iam.delete_role_policy(RoleName=role_name, PolicyName=name)
            for name in iam.list_role_policies(RoleName=role_name)["PolicyNames"]
        ],
        lambda: iam.delete_role(RoleName=role_name),
    )
    for step in steps:
        try:
            step()
        except ClientError as err:
            if err.response["Error"]["Code"] != "NoSuchEntity":
                raise


def _delete_sg_best_effort(ec2, sg_id, timeout_s=300.0, interval_s=10.0):
    """Delete the security group, retrying while the mount target's interfaces still hold it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
