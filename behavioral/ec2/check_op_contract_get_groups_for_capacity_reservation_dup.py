"""op-contract-get-groups-for-capacity-reservation-dup."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-groups-for-capacity-reservation-dup"
GROUP = "error-semantics"
SERVICES = ["ec2"]

DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."
MALFORMED_CODE = "InvalidCapacityReservationId.Malformed"
MALFORMED_MESSAGE = "Capacity Reservation ID '{cr_id}' is malformed"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetGroupsForCapacityReservation with DryRun fails with DryRunOperation and the standard message
    whether or not the reservation exists; a made-up reservation id fails with the malformed-id code
    and its exact message."""
    ec2 = ctx.client("ec2")
    bogus_cr_id = "cr-0123456789abcdef0"

    # Success-path contract proxy: DryRun proves the request is well-formed and
    # authorized, independent of whether the reservation actually exists.
    dry_run_code, dry_run_message = _error(
        lambda: ec2.get_groups_for_capacity_reservation(
            CapacityReservationId=bogus_cr_id, DryRun=True
        )
    )
    assert dry_run_code == "DryRunOperation", f"expected DryRunOperation, got {dry_run_code!r}"
    assert dry_run_message == DRY_RUN_MESSAGE, (
        f"expected message {DRY_RUN_MESSAGE!r}, got {dry_run_message!r}"
    )

    # Error boundary: without DryRun, a made-up reservation id must be rejected -
    # real AWS treats this id shape as Malformed rather than NotFound.
    code, message = _error(
        lambda: ec2.get_groups_for_capacity_reservation(CapacityReservationId=bogus_cr_id)
    )
    assert code == MALFORMED_CODE, f"expected {MALFORMED_CODE}, got {code!r}"
    expected_message = MALFORMED_MESSAGE.format(cr_id=bogus_cr_id)
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
