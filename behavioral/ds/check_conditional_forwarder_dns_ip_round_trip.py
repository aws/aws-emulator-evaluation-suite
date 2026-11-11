"""conditional-forwarder-dns-ip-round-trip."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "conditional-forwarder-dns-ip-round-trip"
GROUP = "representation"
SERVICES = ["ds"]

# Unique to this check: a run deletes the directory it creates, so no other check may find it.
_SHARED_MAD_NAME = "sim2ds4d4a3b9f.sim2real.test"
_SHARED_MAD_VPC_TAG = "sim2real-ds-shared-mad-vpc3"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeConditionalForwarders returns DnsIpAddrs in the exact order supplied to
    CreateConditionalForwarder on an Active AWS Managed Microsoft AD directory."""
    ds = ctx.client("ds")
    directory_id = _get_or_create_shared_microsoft_ad(ctx)

    remote_domain = f"onprem.{ctx.unique_name('sim2realcf')}.test"
    dns_ips = ["203.0.113.11", "198.51.100.22", "192.0.2.33"]

    _retry_directory_busy(lambda: ds.create_conditional_forwarder(
        DirectoryId=directory_id, RemoteDomainName=remote_domain, DnsIpAddrs=dns_ips
    ))
    ctx.on_cleanup(lambda: _safe(lambda: ds.delete_conditional_forwarder(
        DirectoryId=directory_id, RemoteDomainName=remote_domain
    )))

    forwarders = ds.describe_conditional_forwarders(
        DirectoryId=directory_id, RemoteDomainNames=[remote_domain]
    )["ConditionalForwarders"]
    assert len(forwarders) == 1, f"expected exactly one conditional forwarder, got {len(forwarders)}"
    assert forwarders[0]["DnsIpAddrs"] == dns_ips, (
        f"DNS IP order/content drifted: wrote {dns_ips}, read back {forwarders[0]['DnsIpAddrs']}"
    )


# ===== helpers =====

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
    return "Sim2Real-Behav!9Qx"


def _retry_directory_busy(fn, attempts: int = 10, delay_s: float = 12.0):
    """Retry a mutating call that transiently fails with DirectoryUnavailableException (another
    mutation still settling) or ServiceException."""
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
    """The run's shared network and its distinct-AZ subnets, preferred over a dedicated VPC,
    which counts against the account's small VPC quota."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
    by_az = {}
    for s in subnets:
        if s["State"] == "available":
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    # Return every distinct-AZ subnet, not just the first 2: CreateMicrosoftAD can reject an
    # individual AZ as capacity-constrained (see _create_microsoft_ad_trying_subnet_pairs), and
    # the caller needs spare candidates to retry with rather than a single fixed pair.
    subnet_ids = list(by_az.values())
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
        f"directory {directory_id} still at stage={last_stage} after {timeout_s}s "
        "(AWS Managed Microsoft AD provisioning takes ~20-45 minutes)"
    )


_UNSUPPORTED_AZ_SUBNET_RE = re.compile(r"corresponding to subnet:\s*(subnet-[0-9a-f]+)")


def _create_microsoft_ad_trying_subnet_pairs(ctx, vpc_id, subnet_ids):
    """CreateMicrosoftAD can reject one specific AZ of a VPC as capacity-constrained for
    Directory Service ("Failed to locate Availability Zone: ... corresponding to subnet: ...
    This availability zone may be capacity constrained.") even though the subnet itself is
    healthy. The error names the offending subnet, so drop exactly that one and retry with
    the next candidate pair."""
    ds = ctx.client("ds")
    remaining = list(subnet_ids)
    last_exc = None
    while len(remaining) >= 2:
        pair = remaining[:2]
        try:
            resp = ds.create_microsoft_ad(
                Name=_SHARED_MAD_NAME,
                Password=_mad_password(),
                Edition="Standard",
                VpcSettings={"VpcId": vpc_id, "SubnetIds": pair},
                Tags=[
                    {"Key": "Name", "Value": _SHARED_MAD_NAME},
                    {"Key": "sim2real", "Value": "ds-behavioral"},
                ],
            )
            return resp["DirectoryId"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            msg = exc.response.get("Error", {}).get("Message", "")
            if code == "EntityAlreadyExistsException":
                directory_id = _find_directory_id_by_name(ctx, _SHARED_MAD_NAME)
                if directory_id is not None:
                    return directory_id
                raise
            if code == "ClientException" and "Availability Zone" in msg:
                last_exc = exc
                match = _UNSUPPORTED_AZ_SUBNET_RE.search(msg)
                bad = match.group(1) if match else pair[-1]
                remaining = [s for s in remaining if s != bad]
                continue
            raise
    raise last_exc or AssertionError(
        f"no viable 2-subnet, 2-AZ pair for CreateMicrosoftAD among {subnet_ids}"
    )


def _get_or_create_shared_microsoft_ad(ctx) -> str:
    directory_id = _find_directory_id_by_name(ctx, _SHARED_MAD_NAME)
    if directory_id is None:
        vpc_id, subnet_ids = _get_or_create_shared_vpc(ctx, _SHARED_MAD_VPC_TAG, "10.80")
        directory_id = _create_microsoft_ad_trying_subnet_pairs(ctx, vpc_id, subnet_ids)
    # The name is unique to this check, so the directory is this run's to remove, whether it was
    # created here or is a leftover of an earlier run of this check.
    ctx.on_cleanup(lambda: _delete_directory_and_wait(ctx.client("ds"), directory_id))
    return _wait_directory_stage(ctx, directory_id, {"Active"}, {"Failed"}, timeout_s=3600.0)["DirectoryId"]


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
