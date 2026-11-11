"""create-interruptible-capacity-reservation-allocation-invalid-target-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-interruptible-capacity-reservation-allocation-invalid-target-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_BOGUS_CAPACITY_RESERVATION_ID = "cr-0123456789abcdef1"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateInterruptibleCapacityReservationAllocation on an unknown reservation id is refused with
    InvalidCapacityReservationId.NotFound and its exact message, while on a real reservation it allocates 1
    instance and that reservation's available count drops by 1.
    """
    ec2 = ctx.client("ec2")
    az = _pick_availability_zone(ec2)

    reservation_count = 2
    reservation = ec2.create_capacity_reservation(
        InstanceType="t3.micro",
        InstancePlatform="Linux/UNIX",
        AvailabilityZone=az,
        InstanceCount=reservation_count,
        EndDateType="unlimited",
        TagSpecifications=[
            {
                "ResourceType": "capacity-reservation",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-cr-interrupt-")}],
            }
        ],
    )["CapacityReservation"]
    cr_id = reservation["CapacityReservationId"]
    # budget.cleanup_timeout for behavioral/ec2, one deadline shared by both teardowns.
    teardown_deadline: dict = {}
    ctx.on_cleanup(lambda: _cancel_reservation(ec2, cr_id, teardown_deadline))
    assert cr_id != _BOGUS_CAPACITY_RESERVATION_ID, (
        f"real reservation id collided with the bogus target id: {cr_id!r}"
    )

    _poll_until(
        lambda: ec2.describe_capacity_reservations(CapacityReservationIds=[cr_id])[
            "CapacityReservations"
        ][0],
        lambda cr: cr["State"] == "active",
        timeout_s=60.0,
    )

    # --- Negative: a nonexistent target reservation is rejected ---
    code, message = _error(
        lambda: ec2.create_interruptible_capacity_reservation_allocation(
            CapacityReservationId=_BOGUS_CAPACITY_RESERVATION_ID, InstanceCount=1
        )
    )
    assert code == "InvalidCapacityReservationId.NotFound", f"expected InvalidCapacityReservationId.NotFound, got {code!r}"
    assert message == f"The capacity-reservation ID '{_BOGUS_CAPACITY_RESERVATION_ID}' does not exist", message

    # Effect absent: the real reservation's available count is untouched.
    unchanged = ec2.describe_capacity_reservations(CapacityReservationIds=[cr_id])[
        "CapacityReservations"
    ][0]
    assert unchanged["AvailableInstanceCount"] == reservation_count, (
        f"rejected allocation against a bogus target still moved the real reservation's "
        f"available count: expected {reservation_count}, got {unchanged['AvailableInstanceCount']}"
    )

    # --- Positive control: an interruptible allocation from the real reservation succeeds ---
    allocation = ec2.create_interruptible_capacity_reservation_allocation(
        CapacityReservationId=cr_id, InstanceCount=1
    )
    # Reclaim the allocation first: CancelCapacityReservation refuses while it is active.
    ctx.on_cleanup(lambda: _reclaim_allocation(ec2, cr_id, teardown_deadline))
    assert allocation["SourceCapacityReservationId"] == cr_id, (
        f"allocation reports source {allocation['SourceCapacityReservationId']!r}, expected {cr_id!r}"
    )
    assert allocation["TargetInstanceCount"] == 1, (
        f"expected TargetInstanceCount 1, got {allocation['TargetInstanceCount']}"
    )

    after = _poll_until(
        lambda: ec2.describe_capacity_reservations(CapacityReservationIds=[cr_id])[
            "CapacityReservations"
        ][0],
        lambda cr: cr["AvailableInstanceCount"] == reservation_count - 1,
        timeout_s=60.0,
    )
    assert after["AvailableInstanceCount"] == reservation_count - 1, (
        f"source reservation's available count did not drop after the interruptible allocation: {after}"
    )


def _pick_availability_zone(ec2) -> str:
    zones = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ]
    assert zones, "no available Availability Zones in this region"
    return zones[0]["ZoneName"]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed value: {value!r}")


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


_TEARDOWN_RETRY_S = 900.0
_THROTTLE_CODES = ("RequestLimitExceeded", "Throttling")


def _reclaim_allocation(ec2, cr_id: str, shared: dict) -> None:
    """Reclaim every allocated instance back to the source reservation; a gone source is done."""
    deadline = shared.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S)
    while True:
        try:
            ec2.update_interruptible_capacity_reservation_allocation(
                CapacityReservationId=cr_id, TargetInstanceCount=0
            )
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidCapacityReservationId.NotFound":
                return
            if code not in _THROTTLE_CODES or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _cancel_reservation(ec2, cr_id: str, shared: dict) -> None:
    """Cancel the source reservation; retry the refusal while the reclaimed allocation is still
    active, and throttling, every 2 s to the cleanup deadline. A gone reservation is done."""
    deadline = shared.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S)
    while True:
        try:
            ec2.cancel_capacity_reservation(CapacityReservationId=cr_id)
            return
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "InvalidCapacityReservationId.NotFound":
                return
            in_use = err["Code"] == "Unsupported" and "active interruptible capacity allocation" in err.get(
                "Message", ""
            )
            if not (in_use or err["Code"] in _THROTTLE_CODES) or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
