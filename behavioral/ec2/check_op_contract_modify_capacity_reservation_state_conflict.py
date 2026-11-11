"""op-contract-modify-capacity-reservation-state-conflict."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

CHECK = "op-contract-modify-capacity-reservation-state-conflict"
GROUP = "error-semantics"
SERVICES = ["ec2"]
DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."

from behavioral_harness import tags


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyCapacityReservation applies changes while active but rejects them once cancelled."""
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")
    az = _first_available_az(ctx)
    name = ctx.unique_name("sim2real-cr-state-conflict-")

    try:
        created = ec2.create_capacity_reservation(
            InstanceType="t3.micro",
            InstancePlatform="Linux/UNIX",
            AvailabilityZone=az,
            InstanceCount=1,
            EndDateType="unlimited",
            EbsOptimized=False,
            TagSpecifications=[
                {"ResourceType": "capacity-reservation", "Tags": [{"Key": "Name", "Value": name}]}
            ],
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in {"InsufficientCapacity", "InsufficientInstanceCapacity", "InstanceLimitExceeded"}:
            raise AssertionError(f"capacity reservation not creatable in this account/region: {code}")
        raise
    reservation = created["CapacityReservation"]
    reservation_id = reservation["CapacityReservationId"]
    ctx.on_cleanup(lambda: _cancel(ec2, reservation_id))
    assert reservation["State"] in {"active", "pending"}, f"unexpected initial state: {reservation['State']!r}"

    # --- error boundary #1: DryRun must reject while the reservation is still modifiable ---
    dry_code, dry_msg = _error(
        lambda: ec2.modify_capacity_reservation(
            CapacityReservationId=reservation_id, InstanceCount=2, DryRun=True
        )
    )
    assert dry_code == "DryRunOperation", f"expected DryRunOperation, got {dry_code!r}"
    assert dry_msg == DRY_RUN_MESSAGE, f"expected message {DRY_RUN_MESSAGE!r}, got {dry_msg!r}"

    _poll_until(
        lambda: ec2.describe_capacity_reservations(CapacityReservationIds=[reservation_id])[
            "CapacityReservations"
        ][0]["State"],
        lambda s: s == "active",
        timeout_s=60.0,
        interval_s=3.0,
    )

    # --- success path: increase instance count while active ---
    ec2.modify_capacity_reservation(CapacityReservationId=reservation_id, InstanceCount=2)
    updated = _poll_until(
        lambda: ec2.describe_capacity_reservations(CapacityReservationIds=[reservation_id])[
            "CapacityReservations"
        ][0],
        lambda r: r["TotalInstanceCount"] == 2,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert updated["TotalInstanceCount"] == 2, f"expected 2, got {updated['TotalInstanceCount']!r}"

    # --- error boundary #2: once cancelled, modification must be rejected (state conflict) ---
    ec2.cancel_capacity_reservation(CapacityReservationId=reservation_id)
    _poll_until(
        lambda: ec2.describe_capacity_reservations(CapacityReservationIds=[reservation_id])[
            "CapacityReservations"
        ][0]["State"],
        lambda s: s == "cancelled",
        timeout_s=30.0,
        interval_s=2.0,
    )
    conflict_code, conflict_msg = _error(
        lambda: ec2.modify_capacity_reservation(
            CapacityReservationId=reservation_id, InstanceCount=3
        )
    )
    assert conflict_code == "InvalidStateTransition", (
        f"expected InvalidStateTransition, got {conflict_code!r}"
    )
    expected_conflict = "Capacity Reservation cannot be modified as it's already cancelled or expired."
    assert conflict_msg == expected_conflict, f"expected message {expected_conflict!r}, got {conflict_msg!r}"

    # effect-absent: the rejected modify must not have moved the count off the
    # pre-cancellation value, confirmed via an independent read
    after_reject = ec2.describe_capacity_reservations(CapacityReservationIds=[reservation_id])[
        "CapacityReservations"
    ][0]
    assert after_reject["TotalInstanceCount"] == 2, (
        f"rejected modify must not change instance count: expected 2, got "
        f"{after_reject['TotalInstanceCount']!r}"
    )


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


def _cancel(ec2, reservation_id: str) -> None:
    try:
        ec2.cancel_capacity_reservation(CapacityReservationId=reservation_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidCapacityReservationId.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
