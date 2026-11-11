"""op-contract-reject-capacity-reservation-billing-ownership-rejected."""
from __future__ import annotations

import datetime as dt

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-reject-capacity-reservation-billing-ownership-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]

DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RejectCapacityReservationBillingOwnership with DryRun fails with DryRunOperation, a digit-altered
    reservation id fails with InvalidCapacityReservationId.Malformed, and a real reservation with no
    pending request fails with InvalidRequest (exact messages); the reservation stays active."""
    ec2 = ctx.client("ec2")

    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]

    end_date = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=10)
    cr = ec2.create_capacity_reservation(
        InstanceType="t3.micro",
        InstancePlatform="Linux/UNIX",
        AvailabilityZone=az,
        InstanceCount=1,
        EndDateType="limited",
        EndDate=end_date,
        TagSpecifications=[
            {
                "ResourceType": "capacity-reservation",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-cr-")}],
            }
        ],
    )
    cr_id = cr["CapacityReservation"]["CapacityReservationId"]
    ctx.on_cleanup(lambda: _cancel_cr(ec2, cr_id))

    # --- boundary A: DryRun on a real, owned reservation short-circuits ---
    code, message = _error(
        lambda: ec2.reject_capacity_reservation_billing_ownership(DryRun=True, CapacityReservationId=cr_id)
    )
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == DRY_RUN_MESSAGE, f"expected message {DRY_RUN_MESSAGE!r}, got {message!r}"

    # --- boundary B: a digit-altered reservation id is rejected distinctly from the DryRun
    # boundary ---
    # RejectCapacityReservationBillingOwnership rejects a digit-altered CapacityReservationId
    # at format validation itself (InvalidCapacityReservationId.Malformed) and never reaches
    # an existence lookup.
    fake_id = _mutate_id_suffix(cr_id)
    code, message = _error(
        lambda: ec2.reject_capacity_reservation_billing_ownership(CapacityReservationId=fake_id)
    )
    assert code == "InvalidCapacityReservationId.Malformed", f"unexpected code: {code}"
    expected_malformed = f"Capacity Reservation ID '{fake_id}' is malformed"
    assert message == expected_malformed, f"expected message {expected_malformed!r}, got {message!r}"
    assert code != "DryRunOperation", "the malformed-id boundary must be distinct from the DryRun boundary"

    # --- boundary C: the real business-logic contract -- a genuine, resolvable, owned
    # reservation, called for real (no DryRun), with no pending billing assignment request
    # outstanding at all. Verified for real: AWS does not silently no-op this; it rejects with
    # InvalidRequest and a message naming the absent pending request specifically (distinct from
    # both the DryRun short-circuit and the malformed-id / not-found ID-validation boundaries). ---
    try:
        ec2.reject_capacity_reservation_billing_ownership(CapacityReservationId=cr_id)
        raise AssertionError("expected InvalidRequest (no pending billing assignment request), call succeeded")
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == "InvalidRequest", f"expected InvalidRequest, got {err['Code']!r}"
        expected_invalid = (
            f"You do not have any pending billing assignment requests for Capacity Reservation {cr_id}."
        )
        assert err.get("Message") == expected_invalid, (
            f"expected message {expected_invalid!r}, got {err.get('Message')!r}"
        )

    # --- terminal, independent read: none of the three rejected calls above touched the
    # reservation itself ---
    described = ec2.describe_capacity_reservations(CapacityReservationIds=[cr_id])[
        "CapacityReservations"
    ][0]
    assert described["State"] == "active", f"expected the reservation to remain active, got {described['State']!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _mutate_id_suffix(real_id: str) -> str:
    """Shift every hex digit of a real resource id's suffix by one (mod 16).

    Verified for real: for RejectCapacityReservationBillingOwnership specifically, altering *every*
    digit of the suffix is rejected as InvalidCapacityReservationId.Malformed at ID-format
    validation, never reaching an existence lookup -- unlike a single-digit flip, which keeps enough
    of the real id intact to clear format validation and surface
    InvalidCapacityReservationId.NotFound instead. Both are real, distinct boundaries; this check
    exercises the all-digits-shifted one."""
    prefix, _, suffix = real_id.rpartition("-")
    shifted = "".join(format((int(c, 16) + 1) % 16, "x") for c in suffix)
    return f"{prefix}-{shifted}"


def _cancel_cr(ec2, cr_id):
    try:
        ec2.cancel_capacity_reservation(CapacityReservationId=cr_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidCapacityReservationId.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
