"""subnet-created-with-an-ipv6-cidr-block-reads-it-back-associated."""

from __future__ import annotations

import ipaddress
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "subnet-created-with-an-ipv6-cidr-block-reads-it-back-associated"
GROUP = "vpc-networking"
SERVICES = ["ec2"]

VPC_CIDR = "10.231.0.0/16"
SUBNET_CIDR = "10.231.1.0/24"
_ASSOC_ID = re.compile(r"subnet-cidr-assoc-[0-9a-f]{17}")


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


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
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """CreateSubnet with an Ipv6CidrBlock from the VPC's Amazon-provided /56 reads the /64 back as an
    associated block; AssignIpv6AddressOnCreation reads back as set; a /64 outside the VPC range is refused.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-v6subnet-")

    vpc_id = ec2.create_vpc(
        CidrBlock=VPC_CIDR,
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
    blocks = vpc_v6.subnets(new_prefix=64)
    next(blocks)
    subnet_v6 = str(next(blocks))

    created = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=SUBNET_CIDR,
        Ipv6CidrBlock=subnet_v6,
        TagSpecifications=_tagspec("subnet", name),
    )["Subnet"]
    subnet_id = created["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    created_set = created["Ipv6CidrBlockAssociationSet"]
    assert [a["Ipv6CidrBlock"] for a in created_set] == [subnet_v6], (
        f"CreateSubnet answered IPv6 blocks {created_set}, expected exactly {subnet_v6}"
    )

    subnet = _poll(
        lambda: _subnet(ec2, subnet_id),
        lambda s: (
            [a["Ipv6CidrBlockState"]["State"] for a in s["Ipv6CidrBlockAssociationSet"]]
            == ["associated"]
        ),
        what=f"the IPv6 block of {subnet_id} in state associated",
    )
    assoc = subnet["Ipv6CidrBlockAssociationSet"][0]
    assert assoc["Ipv6CidrBlock"] == subnet_v6, (
        f"DescribeSubnets reads the block as {assoc['Ipv6CidrBlock']!r}, expected {subnet_v6!r}"
    )
    assert assoc["Ipv6CidrBlockState"] == {"State": "associated"}, (
        f"the subnet block state reads {assoc['Ipv6CidrBlockState']}"
    )
    assert _ASSOC_ID.fullmatch(assoc["AssociationId"]), (
        f"the association id is {assoc['AssociationId']!r}"
    )
    assert assoc["AssociationId"] == created_set[0]["AssociationId"], (
        f"DescribeSubnets lists association {assoc['AssociationId']!r}, CreateSubnet returned "
        f"{created_set[0]['AssociationId']!r}"
    )
    assert subnet["CidrBlock"] == SUBNET_CIDR, (
        f"the subnet IPv4 block reads {subnet['CidrBlock']!r}"
    )
    assert subnet["AssignIpv6AddressOnCreation"] is False, (
        f"a new subnet starts with AssignIpv6AddressOnCreation false, got {subnet['AssignIpv6AddressOnCreation']!r}"
    )

    ec2.modify_subnet_attribute(SubnetId=subnet_id, AssignIpv6AddressOnCreation={"Value": True})
    assert _subnet(ec2, subnet_id)["AssignIpv6AddressOnCreation"] is True, (
        "AssignIpv6AddressOnCreation must read back true after ModifySubnetAttribute"
    )

    # break exactly one thing: a /64 from just past the end of the VPC's /56
    outside = str(ipaddress.ip_network((int(vpc_v6.network_address) + vpc_v6.num_addresses, 64)))
    got = _error(
        lambda: ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.231.2.0/24", Ipv6CidrBlock=outside)
    )
    want = ("InvalidSubnet.Range", f"The IPv6 CIDR '{outside}' is invalid.")
    assert got == want, (
        f"CreateSubnet with {outside} outside {vpc_v6} answered {got}, expected {want}"
    )
    listed = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    assert [s["SubnetId"] for s in listed] == [subnet_id], (
        f"the refused CreateSubnet must leave only {subnet_id} in {vpc_id}, got {[s['SubnetId'] for s in listed]}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
