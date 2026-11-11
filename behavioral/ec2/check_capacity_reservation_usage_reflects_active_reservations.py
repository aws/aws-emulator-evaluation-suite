"""capacity-reservation-usage-reflects-active-reservations."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "capacity-reservation-usage-reflects-active-reservations"
GROUP = "data-plane"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCapacityReservationUsage's counts match the size of the Capacity Reservation just created."""
    ec2 = ctx.client("ec2")
    az = _pick_availability_zone(ec2)

    resp = ec2.create_capacity_reservation(
        InstanceType="t3.micro",
        InstancePlatform="Linux/UNIX",
        AvailabilityZone=az,
        InstanceCount=2,
        EndDateType="unlimited",
        TagSpecifications=[
            {
                "ResourceType": "capacity-reservation",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-cr-usage-")}],
            }
        ],
    )
    cr_id = resp["CapacityReservation"]["CapacityReservationId"]
    ctx.on_cleanup(lambda: ec2.cancel_capacity_reservation(CapacityReservationId=cr_id))

    usage = _poll_until(
        lambda: ec2.get_capacity_reservation_usage(CapacityReservationId=cr_id),
        lambda u: u["State"] == "active",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert usage["State"] == "active", f"capacity reservation never became active: {usage}"
    assert usage["InstanceType"] == "t3.micro", usage
    assert usage["TotalInstanceCount"] == 2, (
        f"expected TotalInstanceCount=2 (matching InstanceCount at creation), got {usage['TotalInstanceCount']}"
    )
    assert usage["AvailableInstanceCount"] == 2, (
        f"no instances have been launched into the reservation yet, expected AvailableInstanceCount=2, "
        f"got {usage['AvailableInstanceCount']}"
    )


def _pick_availability_zone(ec2) -> str:
    resp = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )
    zones = resp["AvailabilityZones"]
    assert zones, "no available Availability Zones in this region"
    return zones[0]["ZoneName"]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
