"""conditional-forwarder-dns-ip-order-preserved."""
from __future__ import annotations

import itertools
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Directory Service cannot place domain controllers in these zones (CreateMicrosoftAD: "Failed to
# locate Availability Zone: us-west-2d"); subnets there are never offered to it.
_DS_UNSUPPORTED_AZS = {"us-west-2d", "us-east-1e", "us-east-1f", "ca-central-1d"}

CHECK = "conditional-forwarder-dns-ip-order-preserved"
GROUP = "representation"
SERVICES = ["ds"]

_SHARED_MAD_NAME = "sim2dssharedmad3.sim2real.test"
_SHARED_MAD_VPC_TAG = "sim2real-ds-shared-mad-vpc3"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeConditionalForwarders returns DnsIpAddrs in the exact order supplied to
    CreateConditionalForwarder on an Active Managed Microsoft AD directory.
    """
    # CreateConditionalForwarder needs an Active directory. Simple AD is closed to new customers
    # and Managed AD takes 20-45 minutes, so one directory is shared across ds checks.
    directory_desc = _get_or_create_shared_microsoft_ad(ctx)
    directory_id = directory_desc["DirectoryId"]
    assert directory_desc["Stage"] == "Active", (
        f"shared directory did not reach Active (got {directory_desc['Stage']})"
    )
    ds = ctx.client("ds")

    remote_domain = f"{ctx.unique_name('sim2real-dscfwd-')}.example.com"
    dns_ips = ["198.51.100.11", "198.51.100.5", "198.51.100.200"]
    _retry_directory_busy(lambda: ds.create_conditional_forwarder(
        DirectoryId=directory_id, RemoteDomainName=remote_domain, DnsIpAddrs=dns_ips
    ))
    ctx.on_cleanup(lambda: _safe(lambda: ds.delete_conditional_forwarder(
        DirectoryId=directory_id, RemoteDomainName=remote_domain
    )))

    forwarders = ds.describe_conditional_forwarders(
        DirectoryId=directory_id, RemoteDomainNames=[remote_domain]
    )["ConditionalForwarders"]
    assert len(forwarders) == 1, f"expected exactly one conditional forwarder, got {forwarders}"
    assert forwarders[0]["RemoteDomainName"] == remote_domain, (
        f"expected RemoteDomainName {remote_domain!r}, got {forwarders[0]['RemoteDomainName']!r}"
    )
    assert forwarders[0]["DnsIpAddrs"] == dns_ips, (
        f"expected DnsIpAddrs {dns_ips} in exact order, got {forwarders[0]['DnsIpAddrs']}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DirectoryDoesNotExistException",
            "EntityDoesNotExistException",
        ):
            raise


def _mad_password() -> str:
    return "Sim2Real!2024Aa-MAD"


def _retry_directory_busy(fn, attempts: int = 10, delay_s: float = 12.0):
    """Retry a mutation on the shared directory while it fails DirectoryUnavailableException or
    ServiceException because another mutation is still settling."""
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
    """Return every available AZ's subnet: CreateMicrosoftAD can reject a pair as capacity
    constrained with no advance signal, so the caller needs several candidate pairs."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    subnets = sorted((s for s in subnets if s["AvailabilityZone"] not in _DS_UNSUPPORTED_AZS), key=lambda s: s["AvailabilityZone"])
    by_az: dict[str, str] = {}
    for s in subnets:
        if s["State"] == "available":
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < 2:
        return None
    return vpc_id, subnet_ids


def _get_or_create_shared_vpc(ctx, tag_name, cidr_base):
    """Prefer the default VPC, else create or adopt one shared tagged VPC, since concurrent
    checks can exhaust the small VPC quota (VpcLimitExceeded)."""
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


def _wait_directory_stage(ctx, directory_id, terminal_ok, terminal_bad, *, timeout_s=2700.0, interval_s=20.0):
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
        "provisioning continues regardless -- a later re-run will find it Active immediately)"
    )


def _create_microsoft_ad_trying_az_pairs(ds, vpc_id, subnet_ids):
    """CreateMicrosoftAD takes exactly two subnets and can reject a pair as capacity constrained
    with no advance signal, so try every 2-subnet combination before giving up."""
    last_exc = None
    for pair in itertools.combinations(subnet_ids, 2):
        try:
            resp = ds.create_microsoft_ad(
                Name=_SHARED_MAD_NAME,
                Password=_mad_password(),
                Edition="Standard",
                VpcSettings={"VpcId": vpc_id, "SubnetIds": list(pair)},
            )
            return resp["DirectoryId"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ClientException" and "Availability Zone" in str(exc):
                last_exc = exc
                continue
            raise
    raise last_exc


def _get_or_create_shared_microsoft_ad(ctx) -> dict:
    ds = ctx.client("ds")
    directory_id = _find_directory_id_by_name(ctx, _SHARED_MAD_NAME)
    if directory_id is None:
        vpc_id, subnet_ids = _get_or_create_shared_vpc(ctx, _SHARED_MAD_VPC_TAG, "10.80")
        try:
            directory_id = _create_microsoft_ad_trying_az_pairs(ds, vpc_id, subnet_ids)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "EntityAlreadyExistsException":
                directory_id = _find_directory_id_by_name(ctx, _SHARED_MAD_NAME)
                if directory_id is None:
                    raise
            else:
                raise
    return _wait_directory_stage(ctx, directory_id, {"Active"}, {"Failed"})


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
