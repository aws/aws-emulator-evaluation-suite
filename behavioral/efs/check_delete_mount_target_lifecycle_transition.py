"""delete-mount-target-lifecycle-transition."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-mount-target-lifecycle-transition"
GROUP = "state"
SERVICES = ["efs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteMountTarget moves a mount target through deleting -> deleted (NotFound)."""
    efs = ctx.client("efs")
    ec2 = ctx.client("ec2")

    token = ctx.unique_name("sim2real-efs-fs-")
    fs_id = efs.create_file_system(
        CreationToken=token, Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "Name", "Value": token}]
    )["FileSystemId"]
    ctx.on_cleanup(lambda: _delete_fs_best_effort(efs, fs_id))
    _wait_fs_state(efs, fs_id, "available")

    subnet = _pick_subnet(ec2, ctx=ctx)
    default_sg = _default_security_group(ec2, subnet["VpcId"])
    mt_id = efs.create_mount_target(
        FileSystemId=fs_id, SubnetId=subnet["SubnetId"], SecurityGroups=[default_sg]
    )["MountTargetId"]
    _wait_mt_state(efs, mt_id, "available")

    efs.delete_mount_target(MountTargetId=mt_id)

    _wait_mt_deleted(efs, mt_id)
    code, msg = _client_error(lambda: efs.describe_mount_targets(MountTargetId=mt_id))
    assert code == "MountTargetNotFound", f"expected MountTargetNotFound reading a deleted mount target, got {code!r}"
    expected_msg = f"Mount target '{mt_id}' does not exist."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # the id is dead, not just absent from reads: a mutation against it must fail the same way
    mutate_code, mutate_msg = _client_error(
        lambda: efs.modify_mount_target_security_groups(MountTargetId=mt_id, SecurityGroups=[default_sg])
    )
    assert mutate_code == "MountTargetNotFound", (
        f"expected a mutation on the deleted mount target to also fail with MountTargetNotFound, "
        f"got {mutate_code!r}"
    )
    expected_mutate_msg = f"Mount target '{mt_id}' does not exist."
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


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_fs_best_effort(efs, fs_id):
    try:
        efs.delete_file_system(FileSystemId=fs_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "FileSystemNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
