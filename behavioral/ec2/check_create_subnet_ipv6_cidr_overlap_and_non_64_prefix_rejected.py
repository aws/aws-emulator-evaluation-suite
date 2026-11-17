"""create-subnet-ipv6-cidr-overlap-and-non-64-prefix-rejected."""
from __future__ import annotations

import ipaddress
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-subnet-ipv6-cidr-overlap-and-non-64-prefix-rejected"
GROUP = "vpc-networking"
SERVICES = ["ec2"]

VPC_CIDR = "10.214.0.0/16"
FIRST_SUBNET_CIDR = "10.214.1.0/24"
CONFLICT_CIDR = "10.214.2.0/24"
PREFIX63_CIDR = "10.214.3.0/24"
PREFIX65_CIDR = "10.214.4.0/24"


def expect_error(fn, code: str, message: str) -> None:
    """Call fn(); assert it raises exactly (code, message). An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == code, (
            f"expected code {code!r}, got {err['Code']!r} ({err.get('Message')!r})"
        )
        assert err.get("Message") == message, (
            f"expected message {message!r}, got {err.get('Message')!r}"
        )
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll(probe, done, *, what, timeout_s=90.0, interval_s=2.0):
    """Call ``probe()`` until ``done(value)``; raises naming ``what`` if ``timeout_s`` elapses."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if done(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{what} not reached within {timeout_s}s; last read {last!r}")


def _an_az(ec2) -> str:
    """Any available availability zone in the region."""
    zones = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    assert zones, "no available availability zone in this region"
    return sorted(z["ZoneName"] for z in zones)[0]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After a dual-stack subnet takes the VPC's first /64, CreateSubnet is refused for an
    Ipv6CidrBlock that repeats that /64 under a new IPv4 CIDR, and for a /63 or a /65
    elsewhere in the VPC's /56; DescribeSubnets by vpc-id still lists only the first subnet.
    """
    ec2 = ctx.client("ec2")
    marker = ctx.unique_name("sim2real-dsipv6-")

    vpc_id = ec2.create_vpc(
        CidrBlock=VPC_CIDR,
        AmazonProvidedIpv6CidrBlock=True,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": marker}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    vpc = _poll(
        lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0],
        lambda v: bool(v.get("Ipv6CidrBlockAssociationSet"))
        and v["Ipv6CidrBlockAssociationSet"][0]["Ipv6CidrBlockState"]["State"] == "associated",
        what="the VPC's Amazon-provided IPv6 CIDR block to associate",
    )
    vpc_ipv6 = vpc["Ipv6CidrBlockAssociationSet"][0]["Ipv6CidrBlock"]
    vpc_net = ipaddress.ip_network(vpc_ipv6)
    assert vpc_net.prefixlen == 56, f"expected a /56 Amazon-provided block, got {vpc_ipv6!r}"

    blocks_64 = list(vpc_net.subnets(new_prefix=64))
    first_64 = blocks_64[0]
    # Disjoint from first_64, so each of the two prefix-length probes below is isolated from
    # the overlap rule tested first: no block either one names was ever actually associated.
    disjoint_63 = next(b for b in vpc_net.subnets(new_prefix=63) if not b.overlaps(first_64))
    disjoint_65 = next(iter(blocks_64[2].subnets(new_prefix=65)))

    az = _an_az(ec2)

    # Positive control: a dual-stack subnet taking the VPC's first /64 succeeds.
    first_subnet = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=FIRST_SUBNET_CIDR, Ipv6CidrBlock=str(first_64),
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": marker}]}],
    )["Subnet"]
    first_subnet_id = first_subnet["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=first_subnet_id))
    first_assoc = first_subnet.get("Ipv6CidrBlockAssociationSet") or []
    assert first_assoc and first_assoc[0]["Ipv6CidrBlock"] == str(first_64), (
        f"first subnet's IPv6 association was {first_assoc!r}, expected {str(first_64)!r}"
    )

    # Break #1: the exact same /64, under a fresh, non-overlapping IPv4 CIDR.
    _overlap = (
        "InvalidSubnet.Conflict",
        f"The IPv6 CIDR '{first_64}' conflicts with another subnet",
    )
    expect_error(
        lambda: ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=CONFLICT_CIDR, Ipv6CidrBlock=str(first_64),
            AvailabilityZone=az,
        ),
        *_overlap,
    )

    # Break #2: a /63 inside the VPC's /56, disjoint from the taken /64.
    _prefix63 = (
        "InvalidParameterValue",
        f"invalid value for parameter ipv6-cidr-block: {disjoint_63}",
    )
    expect_error(
        lambda: ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=PREFIX63_CIDR, Ipv6CidrBlock=str(disjoint_63),
            AvailabilityZone=az,
        ),
        *_prefix63,
    )

    # Break #3: a /65 inside the VPC's /56, disjoint from every block used above.
    _prefix65 = (
        "InvalidParameterValue",
        f"invalid value for parameter ipv6-cidr-block: {disjoint_65}",
    )
    expect_error(
        lambda: ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=PREFIX65_CIDR, Ipv6CidrBlock=str(disjoint_65),
            AvailabilityZone=az,
        ),
        *_prefix65,
    )

    # Terminal read: none of the three refused creates left a phantom subnet behind.
    listed = [s["SubnetId"] for s in ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]]
    assert listed == [first_subnet_id], f"vpc lists {listed!r}, expected only {first_subnet_id!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
