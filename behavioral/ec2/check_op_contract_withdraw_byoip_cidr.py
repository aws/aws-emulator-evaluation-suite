"""op-contract-withdraw-byoip-cidr."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-withdraw-byoip-cidr"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """WithdrawByoipCidr with DryRun fails with DryRunOperation and the standard message for a valid CIDR;
    without DryRun a CIDR never provisioned to the account fails with InvalidCidr.NotFound and its
    exact message."""
    ec2 = ctx.client("ec2")

    plausible_cidr = "203.0.113.0/24"
    dry_run_code, dry_run_message = _error(
        lambda: ec2.withdraw_byoip_cidr(Cidr=plausible_cidr, DryRun=True)
    )
    assert (dry_run_code, dry_run_message) == ("DryRunOperation", _DRY_RUN_MESSAGE), (
        f"expected DryRunOperation {_DRY_RUN_MESSAGE!r}, got {dry_run_code!r} {dry_run_message!r}"
    )

    not_owned = _error(lambda: ec2.withdraw_byoip_cidr(Cidr=plausible_cidr))
    expected = ("InvalidCidr.NotFound", f"The CIDR ({plausible_cidr}) does not exist.")
    assert not_owned == expected, (
        f"expected {expected!r} for an unprovisioned CIDR, got {not_owned!r}"
    )


def _error(fn: Callable[[], Any]):
    """Call fn(); return the (code, message) of its ClientError. A success raises: an
    accepted call is the strongest signal and must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
