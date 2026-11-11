"""op-contract-assignIpv6Addresses."""
from __future__ import annotations

import ipaddress
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-assignIpv6Addresses"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssignIpv6Addresses: a real ENI in an IPv6-enabled subnet gets a new
    IPv6 address carved out of the subnet's actual /64 range; a nonexistent
    network interface ID is a distinct not-found error boundary."""
    ec2 = ctx.client("ec2")

    # A VPC of its own with an Amazon-provided IPv6 block: the default VPC's CIDR blocks are
    # account baseline and never changed.
    vpc_id = _create_vpc_with_retry(
        ec2,
        CidrBlock="10.241.0.0/16",
        AmazonProvidedIpv6CidrBlock=True,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc_and_wait(ec2, vpc_id))
    vpc_ipv6_cidr = _poll_until(
        lambda: _vpc_ipv6_cidr(ec2, vpc_id),
        lambda cidr: cidr is not None,
        timeout_s=60,
    )

    subnet_ipv4, subnet_ipv6 = _pick_free_subnet_cidrs(ec2, vpc_id, vpc_ipv6_cidr)
    assert subnet_ipv4 is not None and subnet_ipv6 is not None, (
        "no free IPv4/IPv6 subnet range available in the VPC"
    )

    az = ec2.describe_availability_zones(
        Filters=[
            {"Name": "region-name", "Values": [ctx.region]},
            {"Name": "state", "Values": ["available"]},
        ]
    )["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=subnet_ipv4,
        Ipv6CidrBlock=subnet_ipv6,
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_subnet_with_retry(ec2, subnet_id))

    eni_id = ec2.create_network_interface(
        SubnetId=subnet_id,
        TagSpecifications=[
            {"ResourceType": "network-interface", "Tags": [{"Key": "sim2real", "Value": "1"}]}
        ],
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni_id))

    resp = ec2.assign_ipv6_addresses(NetworkInterfaceId=eni_id, Ipv6AddressCount=1)
    assigned = resp["AssignedIpv6Addresses"]
    assert len(assigned) == 1, assigned
    subnet_net = ipaddress.ip_network(subnet_ipv6)
    assert ipaddress.ip_address(assigned[0]) in subnet_net, (assigned[0], subnet_ipv6)

    described = ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])[
        "NetworkInterfaces"
    ][0]
    described_ipv6 = {a["Ipv6Address"] for a in described.get("Ipv6Addresses", [])}
    assert assigned[0] in described_ipv6, (assigned, described_ipv6)

    # distinct error boundary: a well-formed but nonexistent network
    # interface ID must be rejected with a NotFound error.
    code, message = _error_of(
        lambda: ec2.assign_ipv6_addresses(
            NetworkInterfaceId="eni-00000000000000000", Ipv6AddressCount=1
        )
    )
    assert code == "InvalidNetworkInterfaceID.NotFound", f"unexpected code {code!r}"
    assert message == "The interface ID 'eni-00000000000000000' does not exist", message


# ===== helpers =====
def _pick_free_subnet_cidrs(ec2, vpc_id, vpc_ipv6_cidr, *, ipv4_prefix: int = 24, ipv6_prefix: int = 64):
    """Pick an IPv4 and an IPv6 CIDR block for a new subnet that overlap no subnet already in
    the VPC."""
    existing = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    used_v4 = [ipaddress.ip_network(s["CidrBlock"]) for s in existing]
    used_v6 = [
        ipaddress.ip_network(a["Ipv6CidrBlock"])
        for s in existing
        for a in s.get("Ipv6CidrBlockAssociationSet", [])
    ]

    vpc = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
    ipv4_cidr = None
    for assoc in vpc.get("CidrBlockAssociationSet", []):
        if assoc["CidrBlockState"]["State"] != "associated":
            continue
        network = ipaddress.ip_network(assoc["CidrBlock"])
        if network.prefixlen > ipv4_prefix:
            continue
        for candidate in network.subnets(new_prefix=ipv4_prefix):
            if not any(candidate.overlaps(u) for u in used_v4):
                ipv4_cidr = str(candidate)
                break
        if ipv4_cidr is not None:
            break

    ipv6_cidr = None
    ipv6_pool = ipaddress.ip_network(vpc_ipv6_cidr)
    for candidate in ipv6_pool.subnets(new_prefix=ipv6_prefix):
        if not any(candidate.overlaps(u) for u in used_v6):
            ipv6_cidr = str(candidate)
            break

    return ipv4_cidr, ipv6_cidr


def _create_vpc_with_retry(ec2, *, timeout_s: float = 1500.0, interval_s: float = 20.0, **kwargs):
    """CreateVpc can transiently report VpcLimitExceeded while other
    concurrently-running checks in the same account are still holding VPCs
    (the account-wide VPC quota is shared across everything running right
    now, not just recently-deleted VPCs); poll within a bounded window
    instead of treating that as a hard failure. The window is kept well
    inside this check's own overall execution budget so a single retry
    helper invocation can never by itself exhaust the check's total time
    budget."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ec2.create_vpc(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "VpcLimitExceeded" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _error_of(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError("expected a ClientError, call succeeded")


def _delete_vpc_and_wait(ec2, vpc_id: str, *, timeout_s: float = 90.0, interval_s: float = 3.0) -> None:
    """DeleteVpc frees the account-wide VPC quota slot, but the quota is
    shared with every other concurrently-running check; confirm the VPC
    has actually disappeared (rather than firing the delete and moving on)
    so the slot is reliably free before this check's teardown is
    considered complete, which is what the create-with-retry loop above
    (in this and other checks) is relying on. DeleteVpc can also transiently
    fail with DependencyViolation for a brief window right after the
    dependent ENI/subnet report themselves deleted -- their underlying
    cleanup can lag by a few seconds -- so retry the delete call itself
    within the bound instead of a single fire-and-forget attempt; a single
    swallowed DependencyViolation here would otherwise leak the VPC (and
    its quota slot) permanently."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_vpc(VpcId=vpc_id)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidVpcID.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    while True:
        try:
            ec2.describe_vpcs(VpcIds=[vpc_id])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidVpcID.NotFound":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"VPC {vpc_id} still listed {timeout_s}s after DeleteVpc")
        time.sleep(interval_s)


def _delete_subnet_with_retry(
    ec2, subnet_id: str, *, timeout_s: float = 60.0, interval_s: float = 3.0
) -> None:
    """DeleteSubnet can fail with DependencyViolation for a brief window
    right after the ENI in this subnet reports itself deleted -- the ENI's
    underlying detachment/release can lag its own "deleted" state by a few
    seconds. Retry the delete itself within a bounded window instead of a
    single fire-and-forget call so that lag doesn't leak the subnet (and,
    transitively, the VPC it's the last dependent of, permanently consuming
    its quota slot)."""
    deadline = time.monotonic() + timeout_s
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
            time.sleep(interval_s)


def _vpc_ipv6_cidr(ec2, vpc_id: str):
    resp = ec2.describe_vpcs(VpcIds=[vpc_id])
    vpc = resp["Vpcs"][0]
    for assoc in vpc.get("Ipv6CidrBlockAssociationSet", []):
        if assoc["Ipv6CidrBlockState"]["State"] == "associated":
            return assoc["Ipv6CidrBlock"]
    return None


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
