"""snapshot-create-delete-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "snapshot-create-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["ds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A manual snapshot reaches Completed and appears in the directory's DescribeSnapshots
    inventory; after DeleteSnapshot it is gone, and a second DeleteSnapshot on the same id is
    rejected with the not-found error."""
    ds = ctx.client("ds")
    directory_id = _get_or_create_shared_microsoft_ad(ctx)

    resp = ds.create_snapshot(DirectoryId=directory_id)
    snapshot_id = resp["SnapshotId"]
    ctx.on_cleanup(lambda: _delete_snapshot_if_present(ds, snapshot_id))

    snap = _wait_snapshot_status(ctx, directory_id, snapshot_id, {"Completed"}, {"Failed"})
    assert snap["Status"] == "Completed", f"expected Completed, got {snap['Status']!r}"
    assert snap["DirectoryId"] == directory_id, (
        f"expected DirectoryId {directory_id!r}, got {snap['DirectoryId']!r}"
    )

    inventory = ds.describe_snapshots(DirectoryId=directory_id)["Snapshots"]
    assert any(s["SnapshotId"] == snapshot_id for s in inventory), (
        f"snapshot {snapshot_id} missing from directory {directory_id}'s snapshot inventory"
    )

    ds.delete_snapshot(SnapshotId=snapshot_id)
    _wait_snapshot_gone(ctx, directory_id, snapshot_id)

    inventory_after = ds.describe_snapshots(DirectoryId=directory_id)["Snapshots"]
    assert not any(s["SnapshotId"] == snapshot_id for s in inventory_after), (
        f"deleted snapshot {snapshot_id} still present in directory {directory_id}'s inventory"
    )

    _delete_snapshot_expect_not_found(ds, snapshot_id)


def _ds_password() -> str:
    return "Sim2Real-Behav!9Qx"


def _delete_snapshot_if_present(ds, snapshot_id: str) -> None:
    try:
        ds.delete_snapshot(SnapshotId=snapshot_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "EntityDoesNotExistException":
            raise


def _tag_spec(rtype: str, name: str) -> list:
    return [{
        "ResourceType": rtype,
        "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "ds-behavioral"}],
    }]


def _create_vpc_with_subnets(ctx, cidr: str = "10.96.0.0/16"):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock=cidr, TagSpecifications=_tag_spec("vpc", ctx.unique_name("sim2real-ds-vpc-"))
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ctx.on_cleanup(lambda: _delete_ec2_retrying(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones()["AvailabilityZones"]
        if az["State"] == "available"
    ][:2]
    if len(azs) < 2:
        raise AssertionError("region does not expose at least 2 available AZs for directory subnets")

    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.96.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=_tag_spec("subnet", ctx.unique_name(f"sim2real-ds-subnet{i}-")),
        )["Subnet"]["SubnetId"]
        ec2.get_waiter("subnet_available").wait(SubnetIds=[subnet_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
        ctx.on_cleanup(lambda sid=subnet_id: _delete_ec2_retrying(lambda: ec2.delete_subnet(SubnetId=sid)))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _delete_ec2_retrying(fn, attempts: int = 12, delay_s: float = 15.0) -> None:
    last_exc = None
    for _ in range(attempts):
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("DependencyViolation", "InvalidParameterValue"):
                last_exc = exc
                time.sleep(delay_s)
                continue
            raise
    if last_exc:
        raise last_exc


def _wait_directory_stage(ctx, directory_id, terminal_ok, terminal_bad, timeout_s=2700.0, interval_s=30.0):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    last_stage = None
    while time.monotonic() < deadline:
        resp = ds.describe_directories(DirectoryIds=[directory_id])
        descs = resp.get("DirectoryDescriptions", [])
        if not descs:
            raise AssertionError(f"directory {directory_id} vanished from DescribeDirectories while waiting")
        desc = descs[0]
        last_stage = desc["Stage"]
        if last_stage in terminal_ok:
            return desc
        if last_stage in terminal_bad:
            raise AssertionError(f"directory {directory_id} reached {last_stage}: {desc.get('StageReason')}")
        time.sleep(interval_s)
    raise AssertionError(f"directory {directory_id} stuck at stage={last_stage} after {timeout_s}s")


_SHARED_MAD_NAME = "sim2dssharedmad.sim2real.test"
_SHARED_VPC_TAG_NAME = "sim2real-ds-shared-vpc"


def _find_directory_id_by_name(ctx, name):
    ds = ctx.client("ds")
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = ds.describe_directories(**kwargs)
        for desc in resp.get("DirectoryDescriptions", []):
            if desc.get("Name") == name and desc.get("Stage") not in ("Deleting", "Deleted"):
                return desc["DirectoryId"]
        next_token = resp.get("NextToken")
        if not next_token:
            return None


def _get_or_create_shared_vpc(ctx):
    """Find the shared VPC by tag before creating one, so concurrent checks share a single
    VPC instead of exhausting the per-region VPC quota. Registers no cleanup."""
    ec2 = ctx.client("ec2")

    def _existing():
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "tag:Name", "Values": [_SHARED_VPC_TAG_NAME]}])["Vpcs"]
        return sorted((v for v in vpcs if v["State"] != "deleting"), key=lambda v: v["VpcId"])

    vpcs = _existing()
    if not vpcs:
        try:
            ec2.create_vpc(
                CidrBlock="10.90.0.0/16",
                TagSpecifications=[{
                    "ResourceType": "vpc",
                    "Tags": [
                        {"Key": "Name", "Value": _SHARED_VPC_TAG_NAME},
                        {"Key": "sim2real", "Value": "ds-behavioral"},
                    ],
                }],
            )
        except ClientError:
            pass
        for _ in range(15):
            vpcs = _existing()
            if vpcs:
                break
            time.sleep(2)
    if not vpcs:
        raise AssertionError("failed to create or find the shared sim2real-ds VPC")
    vpc_id = vpcs[0]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    subnet_ids = [s["SubnetId"] for s in subnets if s["State"] == "available"]
    if len(subnet_ids) >= 2:
        return vpc_id, subnet_ids[:2]

    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones()["AvailabilityZones"]
        if az["State"] == "available"
    ][:2]
    if len(azs) < 2:
        raise AssertionError("region does not expose at least 2 available AZs for directory subnets")

    for i, az in enumerate(azs):
        try:
            subnet_id = ec2.create_subnet(
                VpcId=vpc_id,
                CidrBlock=f"10.90.{i}.0/24",
                AvailabilityZone=az,
                TagSpecifications=[{
                    "ResourceType": "subnet",
                    "Tags": [
                        {"Key": "Name", "Value": f"{_SHARED_VPC_TAG_NAME}-subnet{i}"},
                        {"Key": "sim2real", "Value": "ds-behavioral"},
                    ],
                }],
            )["Subnet"]["SubnetId"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidSubnet.Conflict":
                continue
            raise
        ec2.get_waiter("subnet_available").wait(SubnetIds=[subnet_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
        subnet_ids.append(subnet_id)
    if len(subnet_ids) < 2:
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
        subnet_ids = [s["SubnetId"] for s in subnets if s["State"] == "available"]
    return vpc_id, subnet_ids[:2]


def _get_or_create_shared_microsoft_ad(ctx) -> str:
    """Reuse a shared Managed Microsoft AD directory instead of a ~20-45 min create per check.
    Raises while it is still provisioning rather than blocking past the per-check timeout;
    AWS keeps provisioning in the background. Registers no cleanup."""
    ds = ctx.client("ds")
    directory_id = _find_directory_id_by_name(ctx, _SHARED_MAD_NAME)
    if directory_id is None:
        vpc_id, subnet_ids = _get_or_create_shared_vpc(ctx)
        try:
            resp = ds.create_microsoft_ad(
                Name=_SHARED_MAD_NAME,
                Password=_ds_password(),
                Edition="Standard",
                VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
            )
            directory_id = resp["DirectoryId"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "EntityAlreadyExistsException":
                directory_id = _find_directory_id_by_name(ctx, _SHARED_MAD_NAME)
                if directory_id is None:
                    raise
            else:
                raise
    return _wait_directory_stage(
        ctx, directory_id, {"Active"}, {"Failed"}, timeout_s=200.0, interval_s=10.0
    )["DirectoryId"]


def _wait_snapshot_status(ctx, directory_id, snapshot_id, terminal_ok, terminal_bad, timeout_s=2400.0, interval_s=20.0):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = ds.describe_snapshots(DirectoryId=directory_id, SnapshotIds=[snapshot_id])
        snaps = resp.get("Snapshots", [])
        if not snaps:
            raise AssertionError(f"snapshot {snapshot_id} vanished from DescribeSnapshots while waiting")
        snap = snaps[0]
        last_status = snap["Status"]
        if last_status in terminal_ok:
            return snap
        if last_status in terminal_bad:
            raise AssertionError(f"snapshot {snapshot_id} reached {last_status}")
        time.sleep(interval_s)
    raise AssertionError(f"snapshot {snapshot_id} stuck at status={last_status} after {timeout_s}s")


def _delete_snapshot_expect_not_found(ds, snapshot_id: str) -> None:
    try:
        ds.delete_snapshot(SnapshotId=snapshot_id)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
        request_id = exc.response.get("ResponseMetadata", {}).get("RequestId", "")
        assert code == "EntityDoesNotExistException", (
            f"re-deleting the already-deleted snapshot {snapshot_id} should fail with "
            f"EntityDoesNotExistException, got {code!r}"
        )
        expected = f"Snapshot: {snapshot_id} does not exist : RequestId: {request_id}"
        assert message == expected, f"expected {expected!r}, got {message!r}"
        return
    raise AssertionError(
        f"re-deleting the already-deleted snapshot {snapshot_id} unexpectedly succeeded"
    )


def _wait_snapshot_gone(ctx, directory_id, snapshot_id, timeout_s=300.0, interval_s=15.0) -> None:
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = ds.describe_snapshots(DirectoryId=directory_id, SnapshotIds=[snapshot_id])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "EntityDoesNotExistException":
                return
            raise
        if not resp.get("Snapshots"):
            return
        time.sleep(interval_s)
    raise AssertionError(f"snapshot {snapshot_id} still present in DescribeSnapshots after {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
