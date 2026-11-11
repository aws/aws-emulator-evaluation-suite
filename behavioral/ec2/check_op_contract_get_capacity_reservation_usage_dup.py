"""op-contract-get-capacity-reservation-usage-dup."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-capacity-reservation-usage-dup"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetCapacityReservationUsage's DryRun permission check succeeds independently
    of reservation existence, while a real call against a made-up reservation id
    of this shape is rejected as Malformed by AWS's own ID-format validation."""
    ec2 = ctx.client("ec2")
    bogus_cr_id = "cr-0123456789abcdef0"

    # Success-path contract proxy: DryRun proves the request is well-formed and
    # authorized, independent of whether the reservation actually exists.
    dry_run_code, dry_run_message = _error(
        lambda: ec2.get_capacity_reservation_usage(
            CapacityReservationId=bogus_cr_id, DryRun=True
        )
    )
    assert dry_run_code == "DryRunOperation", f"expected DryRunOperation, got {dry_run_code!r}"
    assert dry_run_message == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message {dry_run_message!r}"
    )

    # Error boundary: without DryRun, a made-up reservation id must be rejected -
    # real AWS treats this id shape as Malformed rather than NotFound.
    code, message = _error(
        lambda: ec2.get_capacity_reservation_usage(CapacityReservationId=bogus_cr_id)
    )
    assert code == "InvalidCapacityReservationId.Malformed", (
        f"expected InvalidCapacityReservationId.Malformed, got {code!r}"
    )
    assert message == f"Capacity Reservation ID '{bogus_cr_id}' is malformed", (
        f"unexpected InvalidCapacityReservationId.Malformed message {message!r}"
    )


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that succeeds
    raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
