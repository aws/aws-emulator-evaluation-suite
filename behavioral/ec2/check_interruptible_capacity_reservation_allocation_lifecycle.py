"""interruptible-capacity-reservation-allocation-lifecycle."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags


CHECK = "interruptible-capacity-reservation-allocation-lifecycle"
GROUP = "state-machine"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateInterruptibleCapacityReservationAllocation moves an allocation
    to active, and reducing its target count to zero releases the capacity
    back to the source reservation (status -> canceled)."""
    ec2 = ctx.client("ec2")

    name = ctx.unique_name("sim2real-icra-")
    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]

    source_id = ec2.create_capacity_reservation(
        InstanceType="t3.micro",
        InstancePlatform="Linux/UNIX",
        AvailabilityZone=az,
        InstanceCount=2,
        EndDateType="unlimited",
        TagSpecifications=_tag_spec("capacity-reservation", name),
    )["CapacityReservation"]["CapacityReservationId"]
    ctx.on_cleanup(lambda: _cancel_reservation(ec2, source_id))

    def _source_state():
        return ec2.describe_capacity_reservations(CapacityReservationIds=[source_id])[
            "CapacityReservations"
        ][0]["State"]

    _poll_until(_source_state, lambda s: s == "active", timeout_s=60, interval_s=3)

    created = ec2.create_interruptible_capacity_reservation_allocation(
        CapacityReservationId=source_id, InstanceCount=2
    )
    assert created["SourceCapacityReservationId"] == source_id
    assert created["TargetInstanceCount"] == 2
    # The create call's own response can still be in the transient "CREATING" state (observed on
    # real AWS) before the allocation settles into one of the modeled InterruptibleCapacityReservation
    # AllocationStatus enum values; the poll below is the terminal read that proves settlement.
    assert created["Status"] in (
        "CREATING",
        "pending",
        "active",
        "updating",
    ), f"unexpected status: {created!r}"

    def _alloc_status():
        cr = ec2.describe_capacity_reservations(CapacityReservationIds=[source_id])[
            "CapacityReservations"
        ][0]
        alloc = cr.get("InterruptibleCapacityAllocation")
        return alloc["Status"] if alloc else None

    _poll_until(_alloc_status, lambda s: s == "active", timeout_s=90, interval_s=3)

    # Reduce the allocation to zero: since no instances are running against
    # the interruptible reservation, all capacity is "available" and AWS
    # reclaims it without interruption, cancelling the allocation.
    updated = ec2.update_interruptible_capacity_reservation_allocation(
        CapacityReservationId=source_id, TargetInstanceCount=0
    )
    assert updated["TargetInstanceCount"] == 0

    def _alloc_status_or_gone():
        cr = ec2.describe_capacity_reservations(CapacityReservationIds=[source_id])[
            "CapacityReservations"
        ][0]
        alloc = cr.get("InterruptibleCapacityAllocation")
        if alloc is None:
            return "gone"
        return alloc["Status"]

    final = _poll_until(
        _alloc_status_or_gone, lambda s: s in ("canceled", "gone"), timeout_s=90, interval_s=3
    )
    assert final in ("canceled", "gone")

    # The source reservation regains its full unused capacity.
    source_after = ec2.describe_capacity_reservations(CapacityReservationIds=[source_id])[
        "CapacityReservations"
    ][0]
    assert source_after["AvailableInstanceCount"] == 2


def _tag_spec(resource_type: str, name: str) -> list[dict[str, Any]]:
    return [
        {
            "ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
        }
    ]


def _cancel_reservation(ec2, cr_id: str) -> None:
    """Cancel the reservation; IncorrectState (already cancelled) or NotFound means it is gone."""
    from botocore.exceptions import ClientError

    try:
        ec2.cancel_capacity_reservation(CapacityReservationId=cr_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("IncorrectState", "InvalidCapacityReservationId.NotFound"):
            raise


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
