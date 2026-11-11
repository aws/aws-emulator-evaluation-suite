"""op-contract-cancel-capacity-reservation-fleets."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-cancel-capacity-reservation-fleets"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CancelCapacityReservationFleets cancels a created fleet (one success, state cancelled), and a
    one-character mutation of its id fails InvalidCapacityReservationFleetId.Malformed or .NotFound
    with a message naming the id.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-crfleet-")
    az = _first_available_az(ctx)

    created = ec2.create_capacity_reservation_fleet(
        InstanceTypeSpecifications=[
            {
                "InstanceType": "t3.micro",
                "InstancePlatform": "Linux/UNIX",
                "AvailabilityZone": az,
                "Weight": 1.0,
            }
        ],
        TotalTargetCapacity=1,
        AllocationStrategy="prioritized",
        InstanceMatchCriteria="open",
        TagSpecifications=[
            {
                "ResourceType": "capacity-reservation-fleet",
                "Tags": [{"Key": "Name", "Value": name}],
            }
        ],
    )
    fleet_id = created["CapacityReservationFleetId"]
    ctx.on_cleanup(lambda: _safe_cancel_fleet(ec2, fleet_id))

    # CancelCapacityReservationFleets accepts a fleet still 'submitted', and a low-capacity
    # fleet can stay 'submitted' for a long time, so it is cancelled without waiting for 'active'.
    resp = ec2.cancel_capacity_reservation_fleets(CapacityReservationFleetIds=[fleet_id])
    assert resp["FailedFleetCancellations"] == [], (
        f"expected no failed cancellations for {fleet_id}, got {resp['FailedFleetCancellations']}"
    )
    successes = resp["SuccessfulFleetCancellations"]
    assert len(successes) == 1, f"expected exactly 1 successful cancellation, got {successes}"
    assert successes[0]["CapacityReservationFleetId"] == fleet_id, (
        f"expected cancelled fleet id {fleet_id}, got {successes[0]['CapacityReservationFleetId']}"
    )

    final_state = _poll_until(
        lambda: ec2.describe_capacity_reservation_fleets(CapacityReservationFleetIds=[fleet_id])[
            "CapacityReservationFleets"
        ][0]["State"],
        lambda state: state == "cancelled",
        timeout_s=60,
    )
    assert final_state == "cancelled", f"expected fleet {fleet_id} to reach 'cancelled', got {final_state!r}"

    # A one-character mutation of the real fleet id is rejected synchronously as
    # InvalidCapacityReservationFleetId.Malformed or .NotFound depending on the id, so either
    # is accepted, with a message naming the id.
    last_char = fleet_id[-1]
    replacement = "0" if last_char != "0" else "1"
    bogus_id = fleet_id[:-1] + replacement
    try:
        ec2.cancel_capacity_reservation_fleets(CapacityReservationFleetIds=[bogus_id])
    except ClientError as exc:
        error = exc.response["Error"]
        assert re.match(r"^InvalidCapacityReservationFleetId\.(Malformed|NotFound)$", error["Code"]), (
            f"expected InvalidCapacityReservationFleetId.Malformed or .NotFound for {bogus_id}, got {error}"
        )
        assert error.get("Message"), f"expected a non-empty error message, got {error}"
        assert bogus_id in error["Message"], (
            f"expected the bogus id {bogus_id} named in the error message, got {error['Message']!r}"
        )
        if error["Code"] == "InvalidCapacityReservationFleetId.NotFound":
            assert error["Message"] == f"Capacity Reservation Fleet ID '{bogus_id}' is not found", (
                error["Message"]
            )
    else:
        raise AssertionError(
            f"expected cancel_capacity_reservation_fleets({bogus_id!r}) to raise "
            "InvalidCapacityReservationFleetId.Malformed or .NotFound, but it did not raise"
        )


def _safe_cancel_fleet(ec2, fleet_id: str) -> None:
    try:
        ec2.cancel_capacity_reservation_fleets(CapacityReservationFleetIds=[fleet_id])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidCapacityReservationFleetId.NotFound":
            raise


def _first_available_az(ctx) -> str:
    ec2 = ctx.client("ec2")
    zones = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    return zones[0]["ZoneName"]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
