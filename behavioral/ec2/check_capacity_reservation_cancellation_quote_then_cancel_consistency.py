"""capacity-reservation-cancellation-quote-then-cancel-consistency."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "capacity-reservation-cancellation-quote-then-cancel-consistency"
GROUP = "state-machine"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A cancellation quote for a future-dated committed Capacity Reservation names that reservation (state
    pending or active, with its current configuration), and CancelCapacityReservation with the quote returns
    true and leaves the reservation cancelled or cancelling.
    """
    from datetime import datetime, timedelta, timezone

    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-crquote-")
    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]

    start_date = datetime.now(timezone.utc) + timedelta(days=65)

    try:
        cr = ec2.create_capacity_reservation(
            InstanceType="t3.micro",
            InstancePlatform="Linux/UNIX",
            AvailabilityZone=az,
            InstanceCount=16,  # 16 * 2 vCPUs = 32 vCPUs, the future-dated minimum
            StartDate=start_date,
            CommitmentDuration=14 * 24 * 3600,  # AWS's documented future-dated minimum, 1_209_600s
            DeliveryPreference="incremental",
            InstanceMatchCriteria="targeted",
            TagSpecifications=_tag_spec("capacity-reservation", name),
        )["CapacityReservation"]
    except ClientError as exc:
        raise AssertionError(
            "future-dated Capacity Reservations are not obtainable in this "
            f"account/region/instance-type combination: {exc}"
        )

    cr_id = cr["CapacityReservationId"]
    ctx.on_cleanup(lambda: _cancel_reservation(ec2, cr_id))

    def _cr_state():
        return ec2.describe_capacity_reservations(CapacityReservationIds=[cr_id])[
            "CapacityReservations"
        ][0]["State"]

    # A future-dated reservation is 'assessing' right after creation (a cancellation quote is refused
    # then), so the poll passes through it; 'failed' means AWS could not commit the capacity.
    state = _poll_until(
        _cr_state,
        lambda s: s in ("scheduled", "payment-pending", "active", "delayed", "failed"),
        timeout_s=900,
        interval_s=15,
    )
    if state == "failed":
        raise AssertionError(
            "AWS could not commit to delivering this future-dated Capacity "
            "Reservation (State=failed) in this account -- a real capacity-"
            "planning outcome, not something under test control"
        )

    quote = ec2.create_capacity_reservation_cancellation_quote(CapacityReservationId=cr_id)[
        "CapacityReservationCancellationQuote"
    ]
    quote_id = quote["CapacityReservationCancellationQuoteId"]
    assert quote["CapacityReservationId"] == cr_id, (
        f"quote names a different reservation: expected {cr_id!r}, "
        f"got {quote['CapacityReservationId']!r}"
    )
    assert quote["QuoteState"] in ("pending", "active"), (
        f"expected quote state pending/active, got {quote['QuoteState']!r}"
    )
    assert quote["CurrentConfiguration"] is not None, (
        "quote's CurrentConfiguration is missing -- the quote does not describe "
        "the reservation's current configuration"
    )

    cancel_resp = ec2.cancel_capacity_reservation(
        CapacityReservationId=cr_id,
        QuoteId=quote_id,
        # Required with a QuoteId under an active commitment (omitting it is refused with
        # InvalidParameterValue), and the only value the model defines.
        ApplyCancellationCharges="commitment-wind-down",
    )
    assert cancel_resp["Return"] is True, (
        f"CancelCapacityReservation with QuoteId={quote_id!r} reported "
        f"Return={cancel_resp['Return']!r}, expected True"
    )

    final = _poll_until(
        lambda: ec2.describe_capacity_reservations(CapacityReservationIds=[cr_id])[
            "CapacityReservations"
        ][0],
        lambda cr: cr["State"] in ("cancelled", "cancelling"),
        timeout_s=60,
        interval_s=3,
    )
    # The quote's target reservation ends up exactly in the (cancelled or
    # actively cancelling) state the quote was created to describe -- no
    # lingering active/scheduled capacity.
    assert final["State"] in ("cancelled", "cancelling"), (
        f"reservation {cr_id} did not settle into cancelled/cancelling "
        f"after CancelCapacityReservation, last observed State={final['State']!r}"
    )
    assert final["CapacityReservationId"] == cr_id, (
        f"terminal read named a different reservation: expected {cr_id!r}, "
        f"got {final['CapacityReservationId']!r}"
    )


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
