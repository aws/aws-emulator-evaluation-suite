"""create-mount-target-lifecycle-transition."""
from __future__ import annotations

import ipaddress
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-mount-target-lifecycle-transition"
GROUP = "state"
SERVICES = ["efs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateMountTarget moves a mount target through creating -> available with an IP in the subnet CIDR."""
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

    created = efs.create_mount_target(
        FileSystemId=fs_id, SubnetId=subnet["SubnetId"], SecurityGroups=[default_sg]
    )
    mt_id = created["MountTargetId"]
    ctx.on_cleanup(lambda: _delete_mt_best_effort(efs, mt_id))

    assert created["LifeCycleState"] in ("creating", "available"), (
        f"expected an initial LifeCycleState of creating or available, got {created['LifeCycleState']!r}"
    )
    assert created["FileSystemId"] == fs_id, (
        f"expected the mount target's FileSystemId to be {fs_id!r}, got {created['FileSystemId']!r}"
    )

    final = _poll_until(
        lambda: efs.describe_mount_targets(MountTargetId=mt_id)["MountTargets"][0],
        lambda mt: mt["LifeCycleState"] == "available",
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert final["LifeCycleState"] == "available", (
        f"expected LifeCycleState available after polling, got {final['LifeCycleState']!r}"
    )
    ip = ipaddress.ip_address(final["IpAddress"])
    cidr = ipaddress.ip_network(subnet["CidrBlock"])
    assert ip in cidr, f"{ip} not within subnet CIDR {cidr}"

    # independent side-channel: the file system's own mount-target collection, filtered by
    # FileSystemId rather than the MountTargetId used above, must show exactly the one we created
    by_fs = efs.describe_mount_targets(FileSystemId=fs_id)["MountTargets"]
    assert len(by_fs) == 1, f"expected exactly 1 mount target for {fs_id}, found {len(by_fs)}"
    assert by_fs[0]["MountTargetId"] == mt_id, (
        f"expected the file system's sole mount target to be {mt_id}, got {by_fs[0]['MountTargetId']}"
    )


# ===== shared helpers =====
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


def _delete_fs_best_effort(efs, fs_id):
    try:
        efs.delete_file_system(FileSystemId=fs_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "FileSystemNotFound":
            raise


def _delete_mt_best_effort(efs, mt_id):
    try:
        efs.delete_mount_target(MountTargetId=mt_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "MountTargetNotFound":
            raise
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        try:
            efs.describe_mount_targets(MountTargetId=mt_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "MountTargetNotFound":
                return
            raise
        time.sleep(2.0)
    raise AssertionError(f"mount target {mt_id} still present 120s after DeleteMountTarget")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
