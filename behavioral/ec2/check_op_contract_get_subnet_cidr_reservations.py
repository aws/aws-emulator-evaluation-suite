"""op-contract-get-subnet-cidr-reservations."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "op-contract-get-subnet-cidr-reservations"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSubnetCidrReservations lists a real prefix reservation carved out of a subnet;
    a nonexistent subnet ID is rejected as NotFound."""
    ec2 = ctx.client("ec2")

    # Creates a subnet in the run's shared network VPC; the reservation does not need an
    # exclusive VPC.
    vpc_id = _get_default_vpc(ec2, ctx=ctx)

    subnet_id, subnet_cidr = _create_subnet_in_vpc(ec2, vpc_id, ctx.unique_name("sim2real-scr-subnet-"))
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    reservation_cidr = _first_subblock(subnet_cidr, new_prefix=28)
    reservation = ec2.create_subnet_cidr_reservation(
        SubnetId=subnet_id,
        Cidr=reservation_cidr,
        ReservationType="prefix",
    )["SubnetCidrReservation"]
    reservation_id = reservation["SubnetCidrReservationId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet_cidr_reservation(SubnetCidrReservationId=reservation_id))

    # success-path contract: the reservation we just created is listed against its subnet.
    reservations = ec2.get_subnet_cidr_reservations(SubnetId=subnet_id)["SubnetIpv4CidrReservations"]
    match = next((r for r in reservations if r["SubnetCidrReservationId"] == reservation_id), None)
    assert match is not None, f"reservation {reservation_id} missing from {reservations!r}"
    assert match["Cidr"] == reservation_cidr, f"expected Cidr={reservation_cidr!r}, got {match['Cidr']!r}"
    assert match["ReservationType"] == "prefix", f"expected ReservationType='prefix', got {match['ReservationType']!r}"
    assert match["SubnetId"] == subnet_id, f"expected SubnetId={subnet_id!r}, got {match['SubnetId']!r}"

    # error boundary: well-formed but nonexistent subnet ID -> NotFound-class error.
    bogus_id = _bogus_id_like(subnet_id)
    code = _error_code(lambda: ec2.get_subnet_cidr_reservations(SubnetId=bogus_id))
    assert code.endswith(".NotFound") and "subnet" in code.lower(), f"unexpected error code: {code}"


def _get_default_vpc(ec2, *, ctx) -> str:
    """Return the run's shared network VPC id."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    return vpcs[0]["VpcId"]


def _create_subnet_in_vpc(ec2, vpc_id: str, name_tag: str):
    """Create a subnet inside vpc_id, picking a /24 that doesn't overlap any subnet
    already there (default VPCs and any concurrently-running check may already occupy
    parts of the CIDR space, so probe candidates and retry on conflict rather than
    hardcoding one)."""
    import ipaddress
    from botocore.exceptions import ClientError

    vpc = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
    vpc_cidr = ipaddress.ip_network(vpc["CidrBlock"])
    tag_specs = [{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name_tag}]}]

    for candidate in vpc_cidr.subnets(new_prefix=24):
        cidr = str(candidate)
        try:
            subnet_id = ec2.create_subnet(
                VpcId=vpc_id, CidrBlock=cidr, TagSpecifications=tag_specs
            )["Subnet"]["SubnetId"]
            return subnet_id, cidr
        except ClientError as err:
            if err.response["Error"]["Code"] in ("InvalidSubnet.Conflict", "InvalidSubnet.Range"):
                continue
            raise
    raise AssertionError(f"no free /24 subnet CIDR available in VPC {vpc_id} ({vpc_cidr})")


def _first_subblock(cidr: str, new_prefix: int) -> str:
    import ipaddress
    network = ipaddress.ip_network(cidr)
    return str(next(network.subnets(new_prefix=new_prefix)))


def _error_code(fn):
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _bogus_id_like(real_id: str) -> str:
    def repl(m):
        return "f" * len(m.group())
    bogus = re.sub(r"[0-9a-f]+$", repl, real_id)
    assert bogus != real_id, "could not derive a distinct bogus id"
    return bogus


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

