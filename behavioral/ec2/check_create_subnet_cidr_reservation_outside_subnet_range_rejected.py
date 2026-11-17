"""create-subnet-cidr-reservation-outside-subnet-range-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-subnet-cidr-reservation-outside-subnet-range-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSubnetCidrReservation rejects a CIDR that falls outside the subnet's own CIDR block,
    while the same range narrowed to fit inside the subnet is accepted and readable.

    Reference: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateSubnetCidrReservation.html
    """
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.211.0.0/16",
        TagSpecifications=[_tag_spec("vpc", ctx.unique_name("sim2real-behav-scr-vpc-"))],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.211.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[_tag_spec("subnet", ctx.unique_name("sim2real-behav-scr-subnet-"))],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    # error boundary: 10.211.2.0/28 does not fall within the subnet's 10.211.1.0/24 block.
    code, message = _error_code(
        lambda: ec2.create_subnet_cidr_reservation(
            SubnetId=subnet_id, Cidr="10.211.2.0/28", ReservationType="prefix"
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    assert message == "Reservation CIDR should within subnet CIDR block 10.211.1.0/24", message

    # effect-absent: the refused reservation must not appear under the subnet.
    reservations = ec2.get_subnet_cidr_reservations(SubnetId=subnet_id)
    all_reservations = reservations["SubnetIpv4CidrReservations"] + reservations["SubnetIpv6CidrReservations"]
    assert all_reservations == [], (
        f"a refused out-of-range reservation must leave the subnet without reservations, got "
        f"{all_reservations!r}"
    )

    # positive control: the same /28 block, moved inside the subnet's own CIDR, is accepted.
    reservation = ec2.create_subnet_cidr_reservation(
        SubnetId=subnet_id, Cidr="10.211.1.128/28", ReservationType="prefix"
    )["SubnetCidrReservation"]
    reservation_id = reservation["SubnetCidrReservationId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet_cidr_reservation(SubnetCidrReservationId=reservation_id))
    assert reservation["Cidr"] == "10.211.1.128/28", (
        f"expected Cidr 10.211.1.128/28 on create response, got {reservation['Cidr']!r}"
    )

    reservations = ec2.get_subnet_cidr_reservations(SubnetId=subnet_id)
    persisted = next(
        r for r in reservations["SubnetIpv4CidrReservations"]
        if r["SubnetCidrReservationId"] == reservation_id
    )
    assert persisted["Cidr"] == "10.211.1.128/28", (
        f"expected the persisted reservation to carry Cidr 10.211.1.128/28, got {persisted['Cidr']!r}"
    )


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
