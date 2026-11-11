"""op-contract-describe-capacity-reservations."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-capacity-reservations"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeCapacityReservations: list-shape success plus the documented
    InvalidCapacityReservationId.Malformed boundary for a syntactically well-formed
    but never-issued reservation ID."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_capacity_reservations()
    assert "CapacityReservations" in resp, f"expected CapacityReservations key, got {resp!r}"
    assert isinstance(resp["CapacityReservations"], list), (
        f"expected CapacityReservations to be a list, got {type(resp['CapacityReservations'])}"
    )

    # Real AWS treats a well-formed-looking cr-<17 hex> id as Malformed rather than
    # NotFound, regardless of whether the hex body is all-zero or mixed, so this is
    # the documented, deterministic
    # boundary for this operation, not a NotFound/Malformed toss-up.
    fake_reservation_id = "cr-" + "0" * 17
    not_found_code, not_found_code_msg = _error(
        lambda: ec2.describe_capacity_reservations(
            CapacityReservationIds=[fake_reservation_id]
        )
    )
    assert not_found_code == "InvalidCapacityReservationId.Malformed", (
        f"expected InvalidCapacityReservationId.Malformed, got {not_found_code}"
    )
    assert not_found_code_msg == f"Capacity Reservation ID '{fake_reservation_id}' is malformed", (
        f"expected the exact InvalidCapacityReservationId.Malformed message, got {not_found_code_msg!r}"
    )

    dry_code, dry_code_msg = _error(lambda: ec2.describe_capacity_reservations(DryRun=True))
    assert dry_code == "DryRunOperation", f"expected DryRunOperation, got {dry_code}"
    assert dry_code_msg == "Request would have succeeded, but DryRun flag is set.", (
        f"expected the exact DryRunOperation message, got {dry_code_msg!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
