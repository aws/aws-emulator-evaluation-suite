"""op-contract-describeCapacityBlockExtensionOfferings."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeCapacityBlockExtensionOfferings"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeCapacityBlockExtensionOfferings's DryRun permission check succeeds
    independently of reservation existence, while a real call against a made-up
    reservation id is rejected as not-found by AWS."""
    ec2 = ctx.client("ec2")
    _require_op(ec2, "describe_capacity_block_extension_offerings")
    bogus_cr_id = "cr-00000000000000000"

    # Success-path contract proxy: DryRun proves the request is well-formed and
    # authorized, independent of whether the reservation actually exists.
    dry_run_code, dry_run_message = _error(
        lambda: ec2.describe_capacity_block_extension_offerings(
            CapacityReservationId=bogus_cr_id,
            CapacityBlockExtensionDurationHours=24,
            DryRun=True,
        )
    )
    assert dry_run_code == "DryRunOperation", f"expected DryRunOperation, got {dry_run_code!r}"
    assert dry_run_message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {dry_run_message!r}"

    # Error boundary: without DryRun, a made-up reservation id must be rejected with the
    # specific not-found error, not merely accepted or bounced with an unrelated code.
    code, message = _error(
        lambda: ec2.describe_capacity_block_extension_offerings(
            CapacityReservationId=bogus_cr_id,
            CapacityBlockExtensionDurationHours=24,
        )
    )
    assert code == "InvalidCapacityReservationId.NotFound", (
        f"expected InvalidCapacityReservationId.NotFound, got {code!r}"
    )
    assert message == f"The capacity-reservation ID '{bogus_cr_id}' does not exist", f"unexpected InvalidCapacityReservationId.NotFound message {message!r}"


def _require_op(client: Any, op_name: str) -> None:

    if not hasattr(client, op_name):
        raise AssertionError(f"ec2 client missing operation {op_name!r} (botocore too old)")


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
