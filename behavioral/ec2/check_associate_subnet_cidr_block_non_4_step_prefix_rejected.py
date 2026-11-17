"""associate-subnet-cidr-block-non-4-step-prefix-rejected."""
from __future__ import annotations

import ipaddress
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "associate-subnet-cidr-block-non-4-step-prefix-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateSubnetCidrBlock rejects an IPv6 CIDR whose prefix length is not a /4 step (the
    documented valid netmask lengths), while the same range narrowed to a /4-step length is
    accepted and visible on the subnet.

    Reference: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AssociateSubnetCidrBlock.html
    """
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.201.0.0/16",
        AmazonProvidedIpv6CidrBlock=True,
        TagSpecifications=[_tag_spec("vpc", ctx.unique_name("sim2real-behav-ascb-vpc-"))],
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
        CidrBlock="10.201.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[_tag_spec("subnet", ctx.unique_name("sim2real-behav-ascb-subnet-"))],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    network_address = ipaddress.ip_network(vpc_ipv6_cidr).network_address
    subnet_cidr_57 = f"{network_address}/57"
    subnet_cidr_60 = f"{network_address}/60"

    # error boundary: /57 is not one of the documented /4-step netmask lengths (/44-/64).
    code, message = _error_code(
        lambda: ec2.associate_subnet_cidr_block(SubnetId=subnet_id, Ipv6CidrBlock=subnet_cidr_57)
    )
    assert code == "InvalidSubnet.Range", f"expected InvalidSubnet.Range, got {code!r}"
    assert message == (
        f"The CIDR '{subnet_cidr_57}' must be one of /44, /48, /52, /56, /60, /64"
    ), message

    # effect-absent: the refused association must not appear on the subnet.
    described = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]
    assert described["Ipv6CidrBlockAssociationSet"] == [], (
        f"a refused /57 association must leave the subnet without an IPv6 CIDR, got "
        f"{described['Ipv6CidrBlockAssociationSet']!r}"
    )

    # positive control: the same base address narrowed to its /4-step neighbour is accepted.
    resp = ec2.associate_subnet_cidr_block(SubnetId=subnet_id, Ipv6CidrBlock=subnet_cidr_60)
    assoc_id = resp["Ipv6CidrBlockAssociation"]["AssociationId"]
    ctx.on_cleanup(_teardown_disassociate(ec2, assoc_id))
    assert resp["Ipv6CidrBlockAssociation"]["Ipv6CidrBlock"] == subnet_cidr_60, (
        f"expected {subnet_cidr_60} on the association response, got "
        f"{resp['Ipv6CidrBlockAssociation']['Ipv6CidrBlock']!r}"
    )

    final = _poll_until(
        lambda: ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]["Ipv6CidrBlockAssociationSet"],
        lambda assocs: any(
            a["AssociationId"] == assoc_id and a["Ipv6CidrBlockState"]["State"] == "associated"
            for a in assocs
        ),
        timeout_s=60,
        interval_s=2,
    )
    match = next(a for a in final if a["AssociationId"] == assoc_id)
    assert match["Ipv6CidrBlock"] == subnet_cidr_60, (
        f"expected the persisted association to carry {subnet_cidr_60}, got {match['Ipv6CidrBlock']!r}"
    )


def _teardown_disassociate(ec2, assoc_id):
    def run_undo() -> None:
        try:
            ec2.disassociate_subnet_cidr_block(AssociationId=assoc_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidSubnetCidrBlockAssociationID.NotFound":
                raise

    return run_undo


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
