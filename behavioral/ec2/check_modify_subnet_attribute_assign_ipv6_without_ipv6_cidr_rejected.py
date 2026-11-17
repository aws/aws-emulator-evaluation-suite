"""modify-subnet-attribute-assign-ipv6-without-ipv6-cidr-rejected."""
from __future__ import annotations

import ipaddress
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "modify-subnet-attribute-assign-ipv6-without-ipv6-cidr-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifySubnetAttribute rejects AssignIpv6AddressOnCreation=true on a subnet with no IPv6
    CIDR block, while the identical call succeeds once an IPv6 CIDR has been associated.

    Reference: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifySubnetAttribute.html
    """
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.221.0.0/16",
        AmazonProvidedIpv6CidrBlock=True,
        TagSpecifications=[_tag_spec("vpc", ctx.unique_name("sim2real-behav-msa-vpc-"))],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    vpc_ipv6_cidr = _poll_until(
        lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0].get("Ipv6CidrBlockAssociationSet", []),
        lambda assocs: bool(assocs) and assocs[0]["Ipv6CidrBlockState"]["State"] == "associated",
        timeout_s=60,
        interval_s=2,
    )[0]["Ipv6CidrBlock"]

    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.221.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[_tag_spec("subnet", ctx.unique_name("sim2real-behav-msa-subnet-"))],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    # error boundary: the subnet carries no IPv6 CIDR block yet.
    code, message = _error_code(
        lambda: ec2.modify_subnet_attribute(
            SubnetId=subnet_id, AssignIpv6AddressOnCreation={"Value": True}
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    assert message == (
        "Invalid value 'true' for assign-ipv6-address-on-creation. Cannot set "
        f"assign-ipv6-address-on-creation to true unless the subnet ({subnet_id}) has an "
        "IPv6 CIDR block associated with it."
    ), message

    # effect-absent: the attribute must still read back false.
    unaffected = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]
    assert unaffected["AssignIpv6AddressOnCreation"] is False, (
        f"a refused AssignIpv6AddressOnCreation update must leave it false, got "
        f"{unaffected['AssignIpv6AddressOnCreation']!r}"
    )

    # positive control: the identical call succeeds once the subnet has an IPv6 CIDR block.
    subnet_ipv6_cidr = str(next(ipaddress.ip_network(vpc_ipv6_cidr).subnets(new_prefix=64)))
    # No teardown is registered for this association: once AssignIpv6AddressOnCreation is set
    # below, AWS refuses to disassociate it while that attribute is true, and deleting the
    # subnet itself (already registered) removes the association along with it.
    assoc_id = ec2.associate_subnet_cidr_block(
        SubnetId=subnet_id, Ipv6CidrBlock=subnet_ipv6_cidr
    )["Ipv6CidrBlockAssociation"]["AssociationId"]
    _poll_until(
        lambda: ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]["Ipv6CidrBlockAssociationSet"],
        lambda assocs: any(
            a["AssociationId"] == assoc_id and a["Ipv6CidrBlockState"]["State"] == "associated"
            for a in assocs
        ),
        timeout_s=60,
        interval_s=2,
    )

    ec2.modify_subnet_attribute(SubnetId=subnet_id, AssignIpv6AddressOnCreation={"Value": True})
    after = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]
    assert after["AssignIpv6AddressOnCreation"] is True, (
        f"expected AssignIpv6AddressOnCreation true after the IPv6 CIDR was associated, got "
        f"{after['AssignIpv6AddressOnCreation']!r}"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error_code(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
