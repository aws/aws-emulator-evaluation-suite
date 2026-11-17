"""create-subnet-ipv6-native-builds-an-ipv6-only-subnet-with-no-ipv4-block."""

from __future__ import annotations

import ipaddress
import time

from behavioral_harness import tags

CHECK = "create-subnet-ipv6-native-builds-an-ipv6-only-subnet-with-no-ipv4-block"
GROUP = "vpc-networking"
SERVICES = ["ec2"]

_V4_BLOCK = "10.244.0.0/16"


def _poll(probe, done, *, what, timeout_s=90.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if done(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{what} not reached within {timeout_s}s; last read {last!r}")


def _tagspec(resource_type, name):
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


def _subnet(ec2, subnet_id):
    return ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """CreateSubnet(Ipv6Native=True) with a /64 from the VPC's IPv6 block builds an IPv6-only
    subnet that DescribeSubnets reads with no IPv4 CidrBlock and the /64 associated.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-v6only-")

    vpc_id = ec2.create_vpc(
        CidrBlock=_V4_BLOCK,
        AmazonProvidedIpv6CidrBlock=True,
        TagSpecifications=_tagspec("vpc", name),
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    vpc_assocs = _poll(
        lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0].get(
            "Ipv6CidrBlockAssociationSet", []
        ),
        lambda a: len(a) == 1 and a[0]["Ipv6CidrBlockState"]["State"] == "associated",
        what=f"the IPv6 association of {vpc_id} in state associated",
    )
    vpc_v6 = ipaddress.ip_network(vpc_assocs[0]["Ipv6CidrBlock"])
    assert vpc_v6.prefixlen == 56, f"the Amazon-provided VPC block is {vpc_v6}, expected a /56"
    subnet_v6 = str(next(vpc_v6.subnets(new_prefix=64)))

    created = ec2.create_subnet(
        VpcId=vpc_id,
        Ipv6Native=True,
        Ipv6CidrBlock=subnet_v6,
        TagSpecifications=_tagspec("subnet", name),
    )["Subnet"]
    subnet_id = created["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    assert created["Ipv6Native"] is True, (
        f"CreateSubnet answered Ipv6Native={created.get('Ipv6Native')!r}, expected True"
    )
    assert "CidrBlock" not in created, (
        f"an IPv6-only subnet's create response must carry no IPv4 CidrBlock, got {created.get('CidrBlock')!r}"
    )
    created_v6 = created["Ipv6CidrBlockAssociationSet"]
    assert [a["Ipv6CidrBlock"] for a in created_v6] == [subnet_v6], (
        f"CreateSubnet answered IPv6 blocks {created_v6}, expected exactly {subnet_v6}"
    )

    subnet = _poll(
        lambda: _subnet(ec2, subnet_id),
        lambda s: (
            [a["Ipv6CidrBlockState"]["State"] for a in s["Ipv6CidrBlockAssociationSet"]]
            == ["associated"]
        ),
        what=f"the IPv6 block of {subnet_id} in state associated",
    )
    assert subnet["Ipv6Native"] is True, (
        f"DescribeSubnets reads Ipv6Native={subnet.get('Ipv6Native')!r}, expected True"
    )
    assert "CidrBlock" not in subnet, (
        f"DescribeSubnets must carry no IPv4 CidrBlock for an IPv6-only subnet, got {subnet.get('CidrBlock')!r}"
    )
    assoc = subnet["Ipv6CidrBlockAssociationSet"][0]
    assert assoc["Ipv6CidrBlock"] == subnet_v6, (
        f"DescribeSubnets reads the IPv6 block as {assoc['Ipv6CidrBlock']!r}, expected {subnet_v6!r}"
    )
    assert assoc["Ipv6CidrBlockState"] == {"State": "associated"}, (
        f"the subnet block state reads {assoc['Ipv6CidrBlockState']}"
    )
    assert assoc["AssociationId"] == created_v6[0]["AssociationId"], (
        f"DescribeSubnets lists association {assoc['AssociationId']!r}, CreateSubnet returned "
        f"{created_v6[0]['AssociationId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
