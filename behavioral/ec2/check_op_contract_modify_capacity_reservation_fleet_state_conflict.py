"""op-contract-modify-capacity-reservation-fleet-state-conflict."""
from __future__ import annotations

import time

CHECK = "op-contract-modify-capacity-reservation-fleet-state-conflict"
GROUP = "error-semantics"
SERVICES = ["ec2"]
DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."

from behavioral_harness import tags


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyCapacityReservationFleet applies changes while active but rejects them once cancelled."""
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")
    az = _first_available_az(ctx)
    name = ctx.unique_name("sim2real-crfleet-")

    try:
        created = ec2.create_capacity_reservation_fleet(
            InstanceTypeSpecifications=[
                {
                    "InstanceType": "t3.micro",
                    "InstancePlatform": "Linux/UNIX",
                    "AvailabilityZone": az,
                    "Weight": 1.0,
                    "EbsOptimized": False,
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
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in {"InsufficientCapacity", "InsufficientInstanceCapacity", "InstanceLimitExceeded"}:
            raise AssertionError(f"capacity reservation fleet not creatable in this account/region: {code}")
        raise
    fleet_id = created["CapacityReservationFleetId"]
    ctx.on_cleanup(lambda: _cancel_fleet(ec2, fleet_id))
    assert created["State"] in {"submitted", "active", "partially_fulfilled"}, (
        f"expected a live post-create state, got {created['State']!r}"
    )

    # --- error boundary #1: DryRun must reject while the fleet is still modifiable ---
    dry_code, dry_msg = _error(
        lambda: ec2.modify_capacity_reservation_fleet(
            CapacityReservationFleetId=fleet_id, TotalTargetCapacity=2, DryRun=True
        )
    )
    assert dry_code == "DryRunOperation", f"expected DryRunOperation, got {dry_code!r}"
    assert dry_msg == DRY_RUN_MESSAGE, f"expected message {DRY_RUN_MESSAGE!r}, got {dry_msg!r}"

    # Fulfillment of a Capacity Reservation Fleet ("submitted" -> "active"/"partially_fulfilled")
    # is asynchronous and can take longer than a minute; it can also fail outright ("failed") if
    # the account/region genuinely lacks capacity for the requested instance type — treat that
    # the same as the upfront InsufficientCapacity check above rather than as a check failure.
    fulfillment_state = _poll_until(
        lambda: _fleet_state(ec2, fleet_id),
        lambda s: s in {"active", "partially_fulfilled", "failed", "expired"},
        timeout_s=240.0,
        interval_s=5.0,
    )
    if fulfillment_state in {"failed", "expired"}:
        raise AssertionError(
            f"capacity reservation fleet did not fulfill in this account/region: "
            f"state={fulfillment_state}"
        )

    # --- success path: increase total target capacity while active ---
    ec2.modify_capacity_reservation_fleet(
        CapacityReservationFleetId=fleet_id, TotalTargetCapacity=2
    )
    updated = _poll_until(
        lambda: ec2.describe_capacity_reservation_fleets(
            CapacityReservationFleetIds=[fleet_id]
        )["CapacityReservationFleets"][0],
        lambda f: f["TotalTargetCapacity"] == 2,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert updated["TotalTargetCapacity"] == 2, (
        f"expected the positive-control modification to land, got {updated['TotalTargetCapacity']!r}"
    )

    # --- error boundary #2: once cancelled, modification must be rejected (state conflict) ---
    # Cancellation is a one-way transition (there is no un-cancel), so this negative has no
    # restore step.
    # The code above (updated["TotalTargetCapacity"] == 2) is the positive control on this same
    # wiring; what follows breaks exactly one thing (cancels the fleet) and re-issues the
    # identical modify call.
    ec2.cancel_capacity_reservation_fleets(CapacityReservationFleetIds=[fleet_id])
    _poll_until(
        lambda: _fleet_state(ec2, fleet_id),
        lambda s: s in {"cancelled", "cancelling"},
        timeout_s=30.0,
        interval_s=2.0,
    )
    conflict_code, conflict_msg = _error(
        lambda: ec2.modify_capacity_reservation_fleet(
            CapacityReservationFleetId=fleet_id, TotalTargetCapacity=3
        )
    )
    assert conflict_code == "InvalidCapacityReservationFleetStateTransition", (
        f"expected InvalidCapacityReservationFleetStateTransition modifying a cancelled "
        f"fleet, got {conflict_code!r}"
    )
    expected_conflict = "Capacity Reservation Fleet cannot be modified as it has already cancelled or expired."
    assert conflict_msg == expected_conflict, f"expected message {expected_conflict!r}, got {conflict_msg!r}"

    # --- effect-absent: the rejected modification must not have landed ---
    unaffected = ec2.describe_capacity_reservation_fleets(CapacityReservationFleetIds=[fleet_id])[
        "CapacityReservationFleets"
    ][0]
    assert unaffected["TotalTargetCapacity"] == 2, (
        f"rejected modification must not change TotalTargetCapacity, got {unaffected['TotalTargetCapacity']!r}"
    )


# ===== helpers =====
def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses fails loudly instead of as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _first_available_az(ctx) -> str:
    ec2 = ctx.client("ec2")
    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    if not azs:
        raise AssertionError("no available Availability Zones found")
    return azs[0]["ZoneName"]


def _fleet_state(ec2, fleet_id: str) -> str:
    return ec2.describe_capacity_reservation_fleets(
        CapacityReservationFleetIds=[fleet_id]
    )["CapacityReservationFleets"][0]["State"]


def _cancel_fleet(ec2, fleet_id: str) -> None:
    """Teardown: cancel the fleet unless it is already ending; a failed cancellation raises."""
    from botocore.exceptions import ClientError

    try:
        fleets = ec2.describe_capacity_reservation_fleets(CapacityReservationFleetIds=[fleet_id])[
            "CapacityReservationFleets"
        ]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidCapacityReservationFleetId.NotFound":
            return
        raise
    if not fleets or fleets[0]["State"] in {"cancelling", "cancelled", "expiring", "expired", "failed"}:
        return
    failed = ec2.cancel_capacity_reservation_fleets(CapacityReservationFleetIds=[fleet_id]).get(
        "FailedFleetCancellations", []
    )
    if failed:
        raise AssertionError(f"cancelling capacity reservation fleet {fleet_id} failed: {failed}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
