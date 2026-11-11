"""microsoft-ad-create-delete-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "microsoft-ad-create-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["ds"]

# Fixed name: creation takes ~20-45 min, past the per-check timeout, so a retry finds the
# directory an earlier attempt started (AWS keeps provisioning it) instead of creating another.
_DEDICATED_MAD_NAME = "sim2dsdedicatedmad.sim2real.test"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateMicrosoftAD reaches Active with the requested Name, Type=MicrosoftAD and
    Edition=Standard, and DeleteDirectory promptly moves it to Deleting (or Deleted)."""
    ds = ctx.client("ds")
    directory_id = _find_directory_id_by_name(ctx, _DEDICATED_MAD_NAME)

    if directory_id is None:
        vpc_id, subnet_ids = _get_or_create_shared_vpc(ctx)
        resp = ds.create_microsoft_ad(
            Name=_DEDICATED_MAD_NAME,
            Password=_ds_password(),
            Edition="Standard",
            VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
            Tags=[{"Key": "sim2real", "Value": "ds-behavioral"}],
        )
        directory_id = resp["DirectoryId"]

    desc = _wait_directory_stage(ctx, directory_id, {"Active"}, {"Failed"}, timeout_s=220.0, interval_s=10.0)
    assert desc["Stage"] == "Active", f"expected Stage=Active, got {desc['Stage']}"
    assert desc["Name"] == _DEDICATED_MAD_NAME, f"expected Name={_DEDICATED_MAD_NAME!r}, got {desc['Name']!r}"
    assert desc["Type"] == "MicrosoftAD", f"expected Type=MicrosoftAD, got {desc['Type']!r}"
    assert desc.get("Edition") == "Standard", f"expected Edition=Standard, got {desc.get('Edition')!r}"

    # Full removal can take tens of minutes, so only the Deleting transition is awaited.
    ds.delete_directory(DirectoryId=directory_id)
    ctx.on_cleanup(lambda: _delete_directory_if_present(ctx, directory_id))

    after_delete = _wait_directory_stage(
        ctx, directory_id, {"Deleting", "Deleted"}, set(), timeout_s=60.0, interval_s=5.0
    )
    assert after_delete["Stage"] in ("Deleting", "Deleted"), (
        f"expected Stage in (Deleting, Deleted) right after DeleteDirectory, got {after_delete['Stage']}"
    )


# ===== helpers =====

def _ds_password() -> str:
    return "Sim2Real-Behav!9Qx"


def _delete_directory_if_present(ctx, directory_id) -> None:
    """Teardown: DeleteDirectory unless the directory is already gone or being deleted."""
    ds = ctx.client("ds")
    try:
        descs = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "EntityDoesNotExistException":
            return
        raise
    if descs and descs[0]["Stage"] not in ("Deleting", "Deleted"):
        ds.delete_directory(DirectoryId=directory_id)


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


_SHARED_VPC_TAG_NAME = "sim2real-ds-shared-vpc"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

