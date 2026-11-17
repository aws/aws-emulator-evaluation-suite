"""create-subnet-rejects-an-ipv6-cidr-block-in-a-vpc-with-no-ipv6-association."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-subnet-rejects-an-ipv6-cidr-block-in-a-vpc-with-no-ipv6-association"
GROUP = "vpc-networking"
SERVICES = ["ec2"]

_V4_BLOCK = "10.245.0.0/16"
_SUBNET_V4_OK = "10.245.1.0/24"
_SUBNET_V4_REFUSED = "10.245.2.0/24"
_DOC_IPV6_CIDR = "2001:db8::/64"


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _tagspec(resource_type, name):
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A VPC with no IPv6 CIDR block refuses CreateSubnet(CidrBlock=..., Ipv6CidrBlock=...) with
    InvalidSubnet.Range, while an IPv4-only CreateSubnet in the same VPC still succeeds.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-noipv6vpc-")

    vpc_id = ec2.create_vpc(
        CidrBlock=_V4_BLOCK,
        TagSpecifications=_tagspec("vpc", name),
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    vpc = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
    assert "Ipv6CidrBlockAssociationSet" not in vpc, (
        f"a VPC created with no Amazon-provided IPv6 block must carry none, got "
        f"{vpc.get('Ipv6CidrBlockAssociationSet')!r}"
    )

    # positive control: an ordinary IPv4-only subnet in the same VPC succeeds
    ok_subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=_SUBNET_V4_OK,
        TagSpecifications=_tagspec("subnet", name),
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=ok_subnet_id))
    assert ec2.describe_subnets(SubnetIds=[ok_subnet_id])["Subnets"][0]["CidrBlock"] == (
        _SUBNET_V4_OK
    ), "DescribeSubnets must read back the IPv4-only subnet's CidrBlock"

    # break exactly one thing: the same VPC, but the create also names an IPv6 block it has none of
    got = _error(
        lambda: ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=_SUBNET_V4_REFUSED,
            Ipv6CidrBlock=_DOC_IPV6_CIDR,
        )
    )
    want = (
        "InvalidSubnet.Range",
        f"The IPv6 CIDR '{_DOC_IPV6_CIDR}' is invalid.",
    )
    assert got == want, (
        f"CreateSubnet with an Ipv6CidrBlock in a VPC with no IPv6 block answered {got}, expected {want}"
    )
    listed = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    assert [s["SubnetId"] for s in listed] == [ok_subnet_id], (
        f"the refused CreateSubnet must leave only {ok_subnet_id} in {vpc_id}, got "
        f"{[s['SubnetId'] for s in listed]}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
