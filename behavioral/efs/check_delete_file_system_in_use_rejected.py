"""delete-file-system-in-use-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-file-system-in-use-rejected"
GROUP = "overly-permissive"
SERVICES = ["efs"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteFileSystem is rejected with FileSystemInUse while a mount target is attached."""
    efs = ctx.client("efs")
    ec2 = ctx.client("ec2")

    token = ctx.unique_name("sim2real-efs-fs-")
    fs_id = efs.create_file_system(
        CreationToken=token, Tags=[{"Key": "Name", "Value": token}, {"Key": "Owner", "Value": "sim2real"}]
    )["FileSystemId"]
    ctx.on_cleanup(lambda: _delete_fs_best_effort(efs, fs_id))
    _wait_fs_state(efs, fs_id, "available")

    subnet = _pick_subnet(ec2, ctx=ctx)
    default_sg = _default_security_group(ec2, subnet["VpcId"])
    mt_id = efs.create_mount_target(
        FileSystemId=fs_id, SubnetId=subnet["SubnetId"], SecurityGroups=[default_sg]
    )["MountTargetId"]
    ctx.on_cleanup(lambda: _delete_mt_best_effort(efs, mt_id))
    _wait_mt_state(efs, mt_id, "available")

    code, msg = _client_error(lambda: efs.delete_file_system(FileSystemId=fs_id))
    assert code == "FileSystemInUse", f"expected FileSystemInUse while a mount target is attached, got {code}"
    expected_msg = f"The file system '{fs_id}' cannot be deleted because it has mount targets. You must delete the mount targets, and then try again."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # effect absent: the file system is still there and still available
    still_there = efs.describe_file_systems(FileSystemId=fs_id)["FileSystems"][0]
    assert still_there["LifeCycleState"] == "available", (
        f"expected the rejected delete to leave the file system available, got {still_there['LifeCycleState']}"
    )

    # positive control: once the mount target is gone, delete succeeds
    efs.delete_mount_target(MountTargetId=mt_id)
    _wait_mt_deleted(efs, mt_id)

    efs.delete_file_system(FileSystemId=fs_id)
    _wait_fs_deleted(efs, fs_id)
    final_code, final_msg = _client_error(lambda: efs.describe_file_systems(FileSystemId=fs_id))
    assert final_code == "FileSystemNotFound", f"expected FileSystemNotFound after delete, got {final_code}"
    expected_final_msg = f"File system '{fs_id}' does not exist."
    assert final_msg == expected_final_msg, f"expected message {expected_final_msg!r}, got {final_msg!r}"

    # a mutation against the now-dead id must fail too, not just a read
    mutate_code, mutate_msg = _client_error(
        lambda: efs.create_mount_target(
            FileSystemId=fs_id, SubnetId=subnet["SubnetId"], SecurityGroups=[default_sg]
        )
    )
    assert mutate_code == "FileSystemNotFound", (
        f"expected a mutation against the deleted file system id to fail with FileSystemNotFound, got {mutate_code}"
    )
    expected_mutate_msg = f"File system '{fs_id}' does not exist."
    assert mutate_msg == expected_mutate_msg, f"expected message {expected_mutate_msg!r}, got {mutate_msg!r}"


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _wait_fs_state(efs, fs_id, state, timeout_s=180.0):
    return _poll_until(
        lambda: efs.describe_file_systems(FileSystemId=fs_id)["FileSystems"][0]["LifeCycleState"],
        lambda s: s == state,
        timeout_s=timeout_s,
        interval_s=5.0,
    )


def _wait_mt_state(efs, mt_id, state, timeout_s=180.0):
    return _poll_until(
        lambda: efs.describe_mount_targets(MountTargetId=mt_id)["MountTargets"][0]["LifeCycleState"],
        lambda s: s == state,
        timeout_s=timeout_s,
        interval_s=5.0,
    )


def _wait_mt_deleted(efs, mt_id, timeout_s=180.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            efs.describe_mount_targets(MountTargetId=mt_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "MountTargetNotFound":
                return
            raise
        time.sleep(5.0)
    raise AssertionError(f"mount target {mt_id} not deleted within {timeout_s}s")


def _wait_fs_deleted(efs, fs_id, timeout_s=180.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            efs.describe_file_systems(FileSystemId=fs_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "FileSystemNotFound":
                return
            raise
        time.sleep(5.0)
    raise AssertionError(f"file system {fs_id} not deleted within {timeout_s}s")


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _pick_subnet(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError(f"VPC {vpc_id} has no subnets to create an EFS mount target")
    return subnets[0]


def _default_security_group(ec2, vpc_id):
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError(f"VPC {vpc_id} has no default security group")
    return sgs[0]["GroupId"]


def _delete_mt_best_effort(efs, mt_id):
    try:
        efs.delete_mount_target(MountTargetId=mt_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "MountTargetNotFound":
            raise


def _delete_fs_best_effort(efs, fs_id):
    try:
        efs.delete_file_system(FileSystemId=fs_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "FileSystemNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
