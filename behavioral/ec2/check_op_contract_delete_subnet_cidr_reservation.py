"""op-contract-delete-subnet-cidr-reservation."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-delete-subnet-cidr-reservation"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteSubnetCidrReservation removes the reservation (freeing the CIDR for reuse);
    a bogus reservation id is rejected with a reservation-specific NotFound."""
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(CidrBlock="10.98.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    _tag(ec2, vpc_id, ctx.unique_name("sim2real-behav-scr-vpc-"))

    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.98.1.0/24")["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    reservation = ec2.create_subnet_cidr_reservation(
        SubnetId=subnet_id, Cidr="10.98.1.0/28", ReservationType="prefix"
    )["SubnetCidrReservation"]
    reservation_id = reservation["SubnetCidrReservationId"]
    ctx.on_cleanup(lambda: _best_effort_delete_reservation(ec2, reservation_id))

    # A second, overlapping reservation is rejected while the first is still held.
    code, msg = _client_error(
        lambda: ec2.create_subnet_cidr_reservation(
            SubnetId=subnet_id, Cidr="10.98.1.0/28", ReservationType="prefix"
        )
    )
    assert code == "InvalidParameterValue", (
        f"expected InvalidParameterValue for an overlapping reservation, got {code!r}"
    )
    expected_msg = "Reservation CIDR 10.98.1.0/28 has overlap with existing reserved CIDR block"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # Success path: delete the reservation and confirm it disappears from Describe.
    resp = ec2.delete_subnet_cidr_reservation(SubnetCidrReservationId=reservation_id)
    assert resp["DeletedSubnetCidrReservation"]["SubnetCidrReservationId"] == reservation_id, (
        f"expected the delete response to echo {reservation_id!r}, got {resp!r}"
    )

    remaining = ec2.get_subnet_cidr_reservations(SubnetId=subnet_id)
    ids = {r["SubnetCidrReservationId"] for r in remaining.get("SubnetIpv4CidrReservations", [])}
    assert reservation_id not in ids, "reservation should be gone after delete"

    # A mutation on the now-dead id (not a fabricated one) must also fail, specifically.
    code, msg = _client_error(
        lambda: ec2.delete_subnet_cidr_reservation(SubnetCidrReservationId=reservation_id)
    )
    assert code == "InvalidSubnetCidrReservationID.NotFound", (
        f"expected a SubnetCidrReservation NotFound code on double-delete, got {code!r}"
    )
    expected_msg = f"The subnet-cidr-reservation ID '{reservation_id}' does not exist"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # Proves the CIDR was actually freed: the same block can now be reserved again.
    replacement = ec2.create_subnet_cidr_reservation(
        SubnetId=subnet_id, Cidr="10.98.1.0/28", ReservationType="prefix"
    )["SubnetCidrReservation"]
    ctx.on_cleanup(
        lambda: _best_effort_delete_reservation(ec2, replacement["SubnetCidrReservationId"])
    )
    assert replacement["Cidr"] == "10.98.1.0/28", (
        f"expected the freed CIDR to be reusable, got {replacement['Cidr']!r}"
    )

    # Error boundary: deleting a reservation id that never existed.
    bogus_id = "scr-00000000000000000"
    code, msg = _client_error(
        lambda: ec2.delete_subnet_cidr_reservation(SubnetCidrReservationId=bogus_id)
    )
    assert code == "InvalidSubnetCidrReservationID.NotFound", (
        f"expected a SubnetCidrReservation NotFound code, got {code!r}"
    )
    expected_msg = f"The subnet-cidr-reservation ID '{bogus_id}' does not exist"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"


def _tag(ec2: Any, resource_id: str, name: str) -> None:
    ec2.create_tags(Resources=[resource_id], Tags=[{"Key": "Name", "Value": name}])


def _best_effort_delete_reservation(ec2: Any, reservation_id: str) -> None:
    try:
        ec2.delete_subnet_cidr_reservation(SubnetCidrReservationId=reservation_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidSubnetCidrReservationID.NotFound":
            raise


def _client_error(fn: Callable[[], Any]) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
