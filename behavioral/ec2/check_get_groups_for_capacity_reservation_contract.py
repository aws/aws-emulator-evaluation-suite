"""op-contract-get-groups-for-capacity-reservation."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-groups-for-capacity-reservation"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetGroupsForCapacityReservation returns an empty group set for a created, ungrouped Capacity
    Reservation and rejects a made-up reservation id with InvalidCapacityReservationId.Malformed and
    its exact message.
    """
    ec2 = ctx.client("ec2")
    cr_id = _create_capacity_reservation(ctx)

    resp = ec2.get_groups_for_capacity_reservation(CapacityReservationId=cr_id)
    # The EC2 query protocol omits list fields entirely when empty, so a freshly
    # created, ungrouped Capacity Reservation may not include this key at all.
    assert resp.get("CapacityReservationGroupSet", []) == [], (
        "a freshly created, ungrouped Capacity Reservation must have no resource groups"
    )

    # Error boundary: a made-up CapacityReservationId of this shape does not pass
    # AWS's own ID-format validation for capacity reservations - real AWS rejects
    # it as Malformed (checked before any existence lookup happens).
    bogus_cr_id = "cr-0123456789abcdef0"
    code, message = _error(
        lambda: ec2.get_groups_for_capacity_reservation(CapacityReservationId=bogus_cr_id)
    )
    assert code == "InvalidCapacityReservationId.Malformed", (
        f"expected InvalidCapacityReservationId.Malformed, got {code!r}"
    )
    expected = f"Capacity Reservation ID '{bogus_cr_id}' is malformed"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _code(exc: ClientError) -> str | None:
    return exc.response.get("Error", {}).get("Code")


def _error(fn):
    """Call fn(); return its error as (code, message). An unexpected SUCCESS raises rather than
    returning a falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_capacity_reservation(ctx) -> str:
    ec2 = ctx.client("ec2")
    zones = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    if not zones:
        raise AssertionError("no available availability zones in this region")
    az = zones[0]["ZoneName"]

    try:
        resp = ec2.create_capacity_reservation(
            InstanceType="t3.micro",
            InstancePlatform="Linux/UNIX",
            AvailabilityZone=az,
            InstanceCount=1,
            EndDateType="unlimited",
            TagSpecifications=[
                {
                    "ResourceType": "capacity-reservation",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-")}],
                }
            ],
        )
    except ClientError as exc:
        raise AssertionError(f"could not create test Capacity Reservation: {_code(exc)}")

    cr_id = resp["CapacityReservation"]["CapacityReservationId"]
    ctx.on_cleanup(lambda: ec2.cancel_capacity_reservation(CapacityReservationId=cr_id))
    return cr_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
