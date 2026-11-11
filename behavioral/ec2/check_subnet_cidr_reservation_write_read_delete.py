"""subnet-cidr-reservation-write-read-delete."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "subnet-cidr-reservation-write-read-delete"
GROUP = "data-plane"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A subnet CIDR reservation's exact CIDR/type is readable right after creation and gone after
    delete, and the dead reservation id is unusable for a further delete."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.171.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    _wait_vpc_available(ec2, vpc_id)

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.171.1.0/24",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    reservation = ec2.create_subnet_cidr_reservation(
        SubnetId=subnet_id,
        Cidr="10.171.1.128/28",
        ReservationType="prefix",
        Description="sim2real-behav-reservation",
    )["SubnetCidrReservation"]
    reservation_id = reservation["SubnetCidrReservationId"]
    assert reservation["Cidr"] == "10.171.1.128/28", (
        f"expected Cidr 10.171.1.128/28 on create response, got {reservation['Cidr']!r}"
    )
    assert reservation["ReservationType"] == "prefix", (
        f"expected ReservationType prefix on create response, got {reservation['ReservationType']!r}"
    )

    found = _find_reservation(ec2, subnet_id, reservation_id)
    assert found is not None, "reservation not visible immediately after creation"
    assert found["Cidr"] == "10.171.1.128/28", (
        f"expected Cidr 10.171.1.128/28 on independent read, got {found['Cidr']!r}"
    )
    assert found["ReservationType"] == "prefix", (
        f"expected ReservationType prefix on independent read, got {found['ReservationType']!r}"
    )
    assert found["Description"] == "sim2real-behav-reservation", (
        f"expected Description sim2real-behav-reservation on independent read, got {found['Description']!r}"
    )

    ec2.delete_subnet_cidr_reservation(SubnetCidrReservationId=reservation_id)

    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if _find_reservation(ec2, subnet_id, reservation_id) is None:
            break
        time.sleep(3)
    else:
        raise AssertionError("deleted subnet CIDR reservation is still visible in GetSubnetCidrReservations")

    # The reservation is gone; deleting the same (now dead) id a second time must fail
    # with the reservation-specific NotFound, not silently succeed again.
    code, message = _error(
        lambda: ec2.delete_subnet_cidr_reservation(SubnetCidrReservationId=reservation_id)
    )
    assert code == "InvalidSubnetCidrReservationID.NotFound", (
        f"expected the SubnetCidrReservation NotFound code deleting the already-deleted "
        f"reservation {reservation_id!r} again, got {code!r}"
    )
    expected_message = f"The subnet-cidr-reservation ID '{reservation_id}' does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _wait_vpc_available(ec2, vpc_id, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        vpc = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
        if vpc["State"] == "available":
            return
        time.sleep(2)
    raise AssertionError("VPC never became available")


def _find_reservation(ec2, subnet_id, reservation_id):
    resp = ec2.get_subnet_cidr_reservations(SubnetId=subnet_id)
    for r in resp.get("SubnetIpv4CidrReservations", []) + resp.get("SubnetIpv6CidrReservations", []):
        if r["SubnetCidrReservationId"] == reservation_id:
            return r
    return None


def _error(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
