"""op-contract-cancel-capacity-reservation."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-cancel-capacity-reservation"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_NEVER_ALLOCATED_ID = "cr-0feedfacefeedface"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CancelCapacityReservation transitions a real, active Capacity Reservation to
    'cancelled', and rejects a Capacity Reservation ID that does not exist with
    InvalidCapacityReservationId.NotFound."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-capres-")
    az = _first_available_az(ctx)

    created = ec2.create_capacity_reservation(
        InstanceType="t3.micro",
        InstancePlatform="Linux/UNIX",
        AvailabilityZone=az,
        InstanceCount=1,
        EndDateType="unlimited",
        TagSpecifications=[
            {"ResourceType": "capacity-reservation", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["CapacityReservation"]
    reservation_id = created["CapacityReservationId"]
    ctx.on_cleanup(lambda: _safe_cancel(ec2, reservation_id))
    assert created["State"] == "active", f"expected active, got {created['State']}"

    resp = ec2.cancel_capacity_reservation(CapacityReservationId=reservation_id)
    assert resp["Return"] is True, f"expected Return=True, got {resp['Return']!r}"

    final = _poll_until(
        lambda: ec2.describe_capacity_reservations(CapacityReservationIds=[reservation_id])[
            "CapacityReservations"
        ][0],
        lambda r: r["State"] == "cancelled",
        timeout_s=60,
    )
    assert final["State"] == "cancelled", f"expected cancelled, got {final['State']}"

    # A fixed, well-formed id that is never allocated: the real ids' shape, cr- plus 17 hex digits
    # with a leading 0.
    code = _error_code(
        lambda: ec2.cancel_capacity_reservation(CapacityReservationId=_NEVER_ALLOCATED_ID)
    )
    assert code == "InvalidCapacityReservationId.NotFound", (
        f"expected InvalidCapacityReservationId.NotFound, got {code}"
    )


def _safe_cancel(ec2, reservation_id: str) -> None:
    try:
        ec2.cancel_capacity_reservation(CapacityReservationId=reservation_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidCapacityReservationId.NotFound":
            raise


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"]
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


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
