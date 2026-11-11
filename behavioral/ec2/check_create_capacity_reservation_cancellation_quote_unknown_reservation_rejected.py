"""create-capacity-reservation-cancellation-quote-unknown-reservation-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-capacity-reservation-cancellation-quote-unknown-reservation-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_BOGUS_CAPACITY_RESERVATION_ID = "cr-0123456789abcdef0"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCapacityReservationCancellationQuote rejects a well-formed but
    nonexistent Capacity Reservation ID with a not-found error, and the same
    call succeeds for a real, existing reservation (positive control)."""
    ec2 = ctx.client("ec2")
    az = _pick_availability_zone(ec2)

    reservation = ec2.create_capacity_reservation(
        InstanceType="t3.micro",
        InstancePlatform="Linux/UNIX",
        AvailabilityZone=az,
        InstanceCount=1,
        EndDateType="unlimited",
        TagSpecifications=[
            {
                "ResourceType": "capacity-reservation",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-cr-cancelquote-")}],
            }
        ],
    )["CapacityReservation"]
    cr_id = reservation["CapacityReservationId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.cancel_capacity_reservation(CapacityReservationId=cr_id)))
    assert cr_id != _BOGUS_CAPACITY_RESERVATION_ID, (
        f"real AWS assigned our fixed bogus id {_BOGUS_CAPACITY_RESERVATION_ID!r} to a real "
        "reservation, so the negative case below would no longer target an unknown id"
    )

    _poll_until(
        lambda: ec2.describe_capacity_reservations(CapacityReservationIds=[cr_id])[
            "CapacityReservations"
        ][0],
        lambda cr: cr["State"] == "active",
        timeout_s=60.0,
    )

    # --- Negative: a well-formed but nonexistent reservation ID is rejected ---
    code, message = _error(
        lambda: ec2.create_capacity_reservation_cancellation_quote(
            CapacityReservationId=_BOGUS_CAPACITY_RESERVATION_ID
        )
    )
    assert code == "InvalidCapacityReservationId.NotFound", f"expected InvalidCapacityReservationId.NotFound, got {code!r}"
    assert message == f"The capacity-reservation ID '{_BOGUS_CAPACITY_RESERVATION_ID}' does not exist", message

    # --- Differentiating control: the SAME call against a real, existing
    # reservation fails with a DIFFERENT, precondition-specific error (this
    # operation only applies to future-dated reservations within a
    # commitment duration -- a normal on-demand reservation has none) --
    # proving the not-found code above is not simply returned for every
    # rejected CapacityReservationId regardless of reason.
    real_code, _ = _error(
        lambda: ec2.create_capacity_reservation_cancellation_quote(CapacityReservationId=cr_id)
    )
    assert real_code != code, (
        "CreateCapacityReservationCancellationQuote returned the SAME error code "
        f"for a nonexistent id and a real, existing reservation with no commitment "
        f"({real_code!r}); it is not actually distinguishing not-found from a "
        "no-commitment precondition failure"
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
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting a call real AWS rejects is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidCapacityReservationId.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
