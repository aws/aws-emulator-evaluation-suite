"""directory-data-access-toggle-enforced."""
from __future__ import annotations

import time
from itertools import combinations

from behavioral_harness import tags
from botocore.exceptions import ClientError

# Directory Service cannot place domain controllers in these zones (CreateMicrosoftAD: "Failed to
# locate Availability Zone: us-west-2d"); subnets there are never offered to it. The zones are
# matched by name because that is how Directory Service's rejections name them; an AZ name maps to a
# different physical zone in each account, so the list holds the names those accounts reject.
_DS_UNSUPPORTED_AZS = {"us-west-2d", "us-east-1e", "us-east-1f", "ca-central-1d"}

CHECK = "directory-data-access-toggle-enforced"
GROUP = "server-side"
SERVICES = ["ds"]

# Unique to this check: a run deletes the directory it creates, so no other check may find it.
_SHARED_MAD_NAME = "sim2ds4ebffd42.sim2real.test"
_SHARED_MAD_VPC_TAG = "sim2real-ds-shared-mad-vpc3"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """EnableDirectoryDataAccess/DisableDirectoryDataAccess flip DescribeDirectoryDataAccess.

    The Data API is only supported on AWS Managed Microsoft AD, so this toggles it on one.
    """
    ds = ctx.client("ds")
    directory_id = _get_or_create_shared_microsoft_ad(ctx)

    # Normalize first: a prior invocation against this SHARED directory may have left data
    # access enabled if it timed out mid-toggle.
    if ds.describe_directory_data_access(DirectoryId=directory_id)["DataAccessStatus"] != "Disabled":
        _retry_directory_busy(lambda: ds.disable_directory_data_access(DirectoryId=directory_id))
        _poll_until(
            lambda: ds.describe_directory_data_access(DirectoryId=directory_id)["DataAccessStatus"] == "Disabled",
            timeout_s=90, interval_s=5,
        )

    initial = ds.describe_directory_data_access(DirectoryId=directory_id)["DataAccessStatus"]
    assert initial == "Disabled", f"expected initial DataAccessStatus Disabled, got {initial}"

    _retry_directory_busy(lambda: ds.enable_directory_data_access(DirectoryId=directory_id))

    def _enabled():
        return ds.describe_directory_data_access(DirectoryId=directory_id)["DataAccessStatus"] == "Enabled"

    assert _poll_until(_enabled, timeout_s=90, interval_s=5), (
        "DataAccessStatus never reached Enabled after EnableDirectoryDataAccess"
    )

    _retry_directory_busy(lambda: ds.disable_directory_data_access(DirectoryId=directory_id))

    def _disabled():
        return ds.describe_directory_data_access(DirectoryId=directory_id)["DataAccessStatus"] == "Disabled"

    assert _poll_until(_disabled, timeout_s=90, interval_s=5), (
        "DataAccessStatus never returned to Disabled after DisableDirectoryDataAccess"
    )


# ===== helpers =====

def _safe(fn) -> None:
    try:
        fn()
    except Exception:
        pass


def _mad_password() -> str:
    return "Sim2Real-Behav!9Qx"


def _retry_directory_busy(fn, attempts: int = 10, delay_s: float = 12.0):
    """The shared directory fixture may be mutated by several checks in this run in
    sequence; a mutating call can transiently fail with DirectoryUnavailableException
    (another mutation still settling) or ServiceException. Retry with backoff rather
    than treat a transient collision as a real fidelity finding."""
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("DirectoryUnavailableException", "ServiceException"):
                last_exc = exc
                time.sleep(delay_s)
                continue
            raise
    raise last_exc


def _poll_until(predicate, *, timeout_s: float, interval_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval_s)
    return predicate()


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


def _default_vpc_subnets(ctx):
    """Prefer the account's default VPC (already DNS-enabled, with a subnet per AZ) over
    creating a dedicated one: the default VPC quota is five per region and several checks
    run at once.

    Returns EVERY available AZ's subnet (not just two): real AWS refuses to place a Microsoft
    AD in some AZs as "capacity constrained", and which AZ is refused varies per account, so the
    caller needs more than one candidate pair to fall back across."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    subnets = sorted((s for s in subnets if s["AvailabilityZone"] not in _DS_UNSUPPORTED_AZS), key=lambda s: s["AvailabilityZone"])
    by_az = {}
    for s in subnets:
        if s["State"] == "available":
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = [by_az[az] for az in sorted(by_az)]
    if len(subnet_ids) < 2:
        return None
    return vpc_id, subnet_ids


def _get_or_create_shared_vpc(ctx, tag_name, cidr_base):
    default = _default_vpc_subnets(ctx)
    if default is not None:
        return default

    ec2 = ctx.client("ec2")

    def _existing():
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "tag:Name", "Values": [tag_name]}])["Vpcs"]
        return sorted((v for v in vpcs if v["State"] != "deleting"), key=lambda v: v["VpcId"])

    vpcs = _existing()
    if not vpcs:
        try:
            ec2.create_vpc(
                CidrBlock=f"{cidr_base}.0.0/16",
                TagSpecifications=[{
                    "ResourceType": "vpc",
                    "Tags": [
                        {"Key": "Name", "Value": tag_name},
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
        raise AssertionError(f"failed to create or find the shared VPC {tag_name}")
    vpc_id = vpcs[0]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    subnet_ids = [s["SubnetId"] for s in subnets if s["State"] == "available"]
    if len(subnet_ids) >= 2:
        return vpc_id, subnet_ids

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
                CidrBlock=f"{cidr_base}.{i}.0/24",
                AvailabilityZone=az,
                TagSpecifications=[{
                    "ResourceType": "subnet",
                    "Tags": [
                        {"Key": "Name", "Value": f"{tag_name}-subnet{i}"},
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
    return vpc_id, subnet_ids


def _wait_directory_stage(ctx, directory_id, terminal_ok, terminal_bad, *, timeout_s=250.0, interval_s=10.0):
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
    raise AssertionError(
        f"shared directory {directory_id} still at stage={last_stage} after {timeout_s}s "
        "(AWS Managed Microsoft AD provisioning genuinely takes ~20-45 minutes; background "
        "provisioning continues regardless -- re-running validate_behavioral once it completes "
        "will find it Active immediately)"
    )


def _is_az_capacity_refusal(exc: ClientError) -> bool:
    """True for CreateMicrosoftAD's refusal of a specific, capacity-constrained AZ.

    Measured against real AWS: ClientException, "Failed to locate Availability Zone: <az>
    corresponding to subnet: <id>. This availability zone may be capacity constrained." Which AZ
    is refused varies per account/region, so no fixed subnet pair is safe to hardcode -- the
    caller retries across every 2-subnet combination instead."""
    error = exc.response.get("Error", {})
    return error.get("Code") == "ClientException" and "Availability Zone" in error.get("Message", "")


def _create_microsoft_ad_with_az_fallback(ds, vpc_id, subnet_ids, *, name, password, edition):
    last_exc = None
    for pair in combinations(subnet_ids, 2):
        try:
            return ds.create_microsoft_ad(
                Name=name,
                Password=password,
                Edition=edition,
                VpcSettings={"VpcId": vpc_id, "SubnetIds": list(pair)},
            )["DirectoryId"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "EntityAlreadyExistsException":
                raise
            if _is_az_capacity_refusal(exc):
                last_exc = exc
                continue
            raise
    raise last_exc or AssertionError(
        f"no 2-subnet combination among {subnet_ids} was accepted for a Microsoft AD directory"
    )


def _get_or_create_shared_microsoft_ad(ctx) -> str:
    ds = ctx.client("ds")
    directory_id = _find_directory_id_by_name(ctx, _SHARED_MAD_NAME)
    if directory_id is None:
        vpc_id, subnet_ids = _get_or_create_shared_vpc(ctx, _SHARED_MAD_VPC_TAG, "10.80")
        try:
            directory_id = _create_microsoft_ad_with_az_fallback(
                ds, vpc_id, subnet_ids,
                name=_SHARED_MAD_NAME, password=_mad_password(), edition="Standard",
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "EntityAlreadyExistsException":
                directory_id = _find_directory_id_by_name(ctx, _SHARED_MAD_NAME)
                if directory_id is None:
                    raise
            else:
                raise
    # The name is unique to this check, so the directory is this run's to remove, whether it was
    # created here or is a leftover of an earlier run of this check.
    ctx.on_cleanup(lambda: _delete_directory_and_wait(ctx.client("ds"), directory_id))
    return _wait_directory_stage(ctx, directory_id, {"Active"}, {"Failed"}, timeout_s=2700.0)["DirectoryId"]


def _delete_directory_and_wait(ds, directory_id, timeout_s=1800.0, interval_s=30.0):
    """Delete a directory and wait until it is gone, so its ENIs and security group leave the
    shared network. DeleteDirectory is retried while the directory is still being created or is
    still shared with another account."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ds.delete_directory(DirectoryId=directory_id)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "EntityDoesNotExistException":
                return
            if "shared" in e.response["Error"].get("Message", "").lower():
                try:
                    shared = ds.describe_shared_directories(OwnerDirectoryId=directory_id)["SharedDirectories"]
                except ClientError as share_err:
                    if share_err.response["Error"]["Code"] != "EntityDoesNotExistException":
                        raise
                    shared = []
                for share in shared:
                    try:
                        ds.unshare_directory(
                            DirectoryId=directory_id,
                            UnshareTarget={"Id": share["SharedAccountId"], "Type": "ACCOUNT"},
                        )
                    except ClientError as unshare_err:
                        if unshare_err.response["Error"]["Code"] not in (
                            "EntityDoesNotExistException", "DirectoryNotSharedException",
                        ):
                            raise
            elif code not in ("ClientException", "InvalidParameterException"):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    while True:
        try:
            found = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "EntityDoesNotExistException":
                return
            raise
        if not found or found[0].get("Stage") == "Deleted":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"directory {directory_id} still exists {timeout_s:.0f}s after DeleteDirectory")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
