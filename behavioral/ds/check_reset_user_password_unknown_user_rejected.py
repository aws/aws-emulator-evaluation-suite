"""reset-user-password-unknown-user-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

# Directory Service cannot place domain controllers in these zones (CreateMicrosoftAD: "Failed to
# locate Availability Zone: us-west-2d"); subnets there are never offered to it.
_DS_UNSUPPORTED_AZS = {"us-west-2d", "us-east-1e", "us-east-1f", "ca-central-1d"}

CHECK = "reset-user-password-unknown-user-rejected"
GROUP = "data-plane"
SERVICES = ["ds"]

NEW_PASSWORD = "Sim2Real!Rotated456"
_SHARED_MAD_NAME = "sim2dssharedmad3.sim2real.test"
_SHARED_MAD_VPC_TAG = "sim2real-ds-shared-mad-vpc3"


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ResetUserPassword for a UserName absent from the directory fails with
    UserDoesNotExistException, while resetting the directory's real default administrator on the
    same directory succeeds, so the rejection is about the username and not the operation."""
    ds = ctx.client("ds")
    directory_id = _get_or_create_shared_microsoft_ad(ctx)

    code, message, request_id = _error(lambda: ds.reset_user_password(
        DirectoryId=directory_id, UserName="sim2real-no-such-user", NewPassword=NEW_PASSWORD
    ))
    assert code == "UserDoesNotExistException", f"expected UserDoesNotExistException, got {code}"
    expected = _USER_MISSING.format(user="sim2real-no-such-user", request_id=request_id)
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # positive control: the default AWS Managed Microsoft AD administrator account exists and
    # can be reset.
    _retry_directory_busy(lambda: ds.reset_user_password(
        DirectoryId=directory_id, UserName="Admin", NewPassword=NEW_PASSWORD
    ))


_USER_MISSING = "User: {user} does not exist. : RequestId: {request_id}"


def _error(fn):
    """Call fn(); return its (error code, message, request id). An unexpected SUCCESS raises:
    a target that accepts what AWS refuses must not read as a plain code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return (
            err.response["Error"]["Code"],
            err.response["Error"].get("Message"),
            err.response.get("ResponseMetadata", {}).get("RequestId", ""),
        )
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _safe(fn) -> None:
    try:
        fn()
    except Exception:
        pass


def _simplead_password() -> str:
    return "Sim2Real!Passw0rd123"


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
    """Prefer the run's shared network (already DNS-enabled, with a subnet per AZ) over
    creating a dedicated one -- sandbox accounts have a small VPC quota and this batch would
    otherwise need several dedicated VPCs at once."""
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
    subnet_ids = list(by_az.values())[:2]
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
    return vpc_id, subnet_ids[:2]


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


def _get_or_create_shared_microsoft_ad(ctx) -> str:
    ds = ctx.client("ds")
    directory_id = _find_directory_id_by_name(ctx, _SHARED_MAD_NAME)
    if directory_id is None:
        vpc_id, subnet_ids = _get_or_create_shared_vpc(ctx, _SHARED_MAD_VPC_TAG, "10.80")
        try:
            resp = ds.create_microsoft_ad(
                Name=_SHARED_MAD_NAME,
                Password=_mad_password(),
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
        ctx, directory_id, {"Active"}, {"Failed"}, timeout_s=2700.0
    )["DirectoryId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
