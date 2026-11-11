"""create-mount-target-duplicate-az-rejected."""
from __future__ import annotations

import ipaddress
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-mount-target-duplicate-az-rejected"
GROUP = "overly-permissive"
SERVICES = ["efs"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second mount target in an occupied AZ is rejected as MountTargetConflict, even from a
    different subnet (the conflict is keyed on the AZ); a mount target in another AZ succeeds."""
    efs = ctx.client("efs")
    ec2 = ctx.client("ec2")

    subnets_by_az = _pick_subnets_multi_az(ec2, min_count=2, ctx=ctx)
    az1, subnet1 = subnets_by_az[0]
    az2, subnet2 = subnets_by_az[1]
    vpc_id = subnet1["VpcId"]
    default_sg = _default_security_group(ec2, vpc_id)

    name_tag = ctx.unique_name("sim2real-efs-mtaz-")
    token = ctx.unique_name("sim2real-efs-fs-")
    fs_id = efs.create_file_system(
        CreationToken=token, Tags=[{"Key": "Name", "Value": name_tag}]
    )["FileSystemId"]
    ctx.on_cleanup(lambda: _delete_fs_best_effort(efs, fs_id))
    _wait_fs_state(efs, fs_id, "available")

    mt1_id = efs.create_mount_target(
        FileSystemId=fs_id, SubnetId=subnet1["SubnetId"], SecurityGroups=[default_sg]
    )["MountTargetId"]
    ctx.on_cleanup(lambda: _delete_mt_best_effort(efs, mt1_id))
    _wait_mt_state(efs, mt1_id, "available")

    code, msg = _client_error(
        lambda: efs.create_mount_target(
            FileSystemId=fs_id, SubnetId=subnet1["SubnetId"], SecurityGroups=[default_sg]
        )
    )
    assert code == "MountTargetConflict", f"expected MountTargetConflict for same-subnet retry, got {code!r}"
    expected_msg = 'mount target already exists in this AZ'
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # effect absent: still exactly one mount target for this file system
    targets = efs.describe_mount_targets(FileSystemId=fs_id)["MountTargets"]
    assert len(targets) == 1, f"expected 1 mount target after rejected same-subnet retry, found {len(targets)}"

    # the conflict is keyed on the AZ, not the subnet: a *different* subnet placed in the same
    # AZ as the existing mount target must be rejected too.
    probe_subnet_id = _create_probe_subnet(ec2, vpc_id, az1)
    ctx.on_cleanup(lambda: _delete_subnet_best_effort(ec2, probe_subnet_id))
    code_same_az, msg_same_az = _client_error(
        lambda: efs.create_mount_target(
            FileSystemId=fs_id, SubnetId=probe_subnet_id, SecurityGroups=[default_sg]
        )
    )
    assert code_same_az == "MountTargetConflict", (
        f"expected MountTargetConflict for a different subnet in the already-occupied AZ {az1}, got {code_same_az!r}"
    )
    expected_same_az_msg = 'mount target already exists in this AZ'
    assert msg_same_az == expected_same_az_msg, f"expected message {expected_same_az_msg!r}, got {msg_same_az!r}"
    targets_same_az = efs.describe_mount_targets(FileSystemId=fs_id)["MountTargets"]
    assert len(targets_same_az) == 1, (
        f"expected 1 mount target after rejected same-AZ/different-subnet retry, found {len(targets_same_az)}"
    )

    # positive control: a mount target in a *different* Availability Zone succeeds
    mt2_id = efs.create_mount_target(
        FileSystemId=fs_id, SubnetId=subnet2["SubnetId"], SecurityGroups=[default_sg]
    )["MountTargetId"]
    ctx.on_cleanup(lambda: _delete_mt_best_effort(efs, mt2_id))
    _wait_mt_state(efs, mt2_id, "available")

    targets_after = efs.describe_mount_targets(FileSystemId=fs_id)["MountTargets"]
    assert len(targets_after) == 2, f"expected 2 mount targets after the different-AZ create, found {len(targets_after)}"


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


def _wait_mt_state(efs, mt_id, state, timeout_s=180.0):
    return _poll_until(
        lambda: efs.describe_mount_targets(MountTargetId=mt_id)["MountTargets"][0]["LifeCycleState"],
        lambda s: s == state,
        timeout_s=timeout_s,
        interval_s=5.0,
    )


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _pick_subnets_multi_az(ec2, min_count=2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s)
    picked = sorted(by_az.items())
    if len(picked) < min_count:
        raise AssertionError(
            f"need subnets in >= {min_count} distinct Availability Zones, found {len(picked)}"
        )
    return picked


def _default_security_group(ec2, vpc_id):
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError(f"VPC {vpc_id} has no default security group")
    return sgs[0]["GroupId"]


def _create_probe_subnet(ec2, vpc_id, az, prefix_len=28):
    """Create a throwaway subnet in *az*, distinct from every subnet already in *vpc_id*."""
    vpc = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
    vpc_cidrs = [
        assoc["CidrBlock"]
        for assoc in vpc.get("CidrBlockAssociationSet", [])
        if assoc.get("CidrBlockState", {}).get("State") == "associated"
    ] or [vpc["CidrBlock"]]
    existing = [
        ipaddress.ip_network(s["CidrBlock"])
        for s in ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    ]
    for vpc_cidr in vpc_cidrs:
        net = ipaddress.ip_network(vpc_cidr)
        if net.prefixlen > prefix_len:
            continue
        for candidate in net.subnets(new_prefix=prefix_len):
            if not any(candidate.overlaps(e) for e in existing):
                created = ec2.create_subnet(
                    VpcId=vpc_id,
                    CidrBlock=str(candidate),
                    AvailabilityZone=az,
                    TagSpecifications=[
                        {
                            "ResourceType": "subnet",
                            "Tags": [{"Key": "Name", "Value": "sim2real-efs-mtaz-probe"}],
                        }
                    ],
                )["Subnet"]
                return created["SubnetId"]
    raise AssertionError(f"no free /{prefix_len} block in VPC {vpc_id} to create a probe subnet in {az}")


def _delete_subnet_best_effort(ec2, subnet_id):
    """Delete the probe subnet; retry DependencyViolation while an ENI in it is released."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            ec2.delete_subnet(SubnetId=subnet_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidSubnetID.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(2.0)


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


def _delete_fs_best_effort(efs, fs_id):
    try:
        efs.delete_file_system(FileSystemId=fs_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "FileSystemNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
