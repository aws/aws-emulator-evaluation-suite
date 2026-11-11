"""op-contract-disable-capacity-manager."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-disable-capacity-manager"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ec2-capacity-manager")
def run(ctx) -> None:
    """DisableCapacityManager on an account where Capacity Manager was never enabled fails with
    CapacityManager.Disabled, DryRun answers DryRunOperation, and GetCapacityManagerAttributes still
    reports it disabled (exact messages)."""
    ec2 = ctx.client("ec2")

    code, message = _error(lambda: ec2.disable_capacity_manager())
    assert code == "CapacityManager.Disabled", (
        f"expected CapacityManager.Disabled, got {code}"
    )
    assert message == "Capacity Manager isn't enabled for this account.", (
        f"unexpected CapacityManager.Disabled message: {message!r}"
    )

    # idempotent: calling disable again on an account where Capacity Manager was
    # never enabled must keep raising the same state error, not a different one.
    code, message = _error(lambda: ec2.disable_capacity_manager())
    assert code == "CapacityManager.Disabled", (
        f"expected CapacityManager.Disabled on repeat call, got {code}"
    )
    assert message == "Capacity Manager isn't enabled for this account.", (
        f"unexpected CapacityManager.Disabled message: {message!r}"
    )

    # The DryRun permission check is evaluated before the state-validation error, so
    # it still reports DryRunOperation rather than CapacityManager.Disabled.
    code, message = _error(lambda: ec2.disable_capacity_manager(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message: {message!r}"
    )

    # Independent read through another operation: GetCapacityManagerAttributes either raises the same
    # CapacityManager.Disabled error or reports CapacityManagerStatus "disabled".
    try:
        attrs = ec2.get_capacity_manager_attributes()
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "CapacityManager.Disabled", (
            f"expected CapacityManager.Disabled from the independent read, "
            f"got {exc.response['Error']}"
        )
        assert exc.response["Error"]["Message"] == "Capacity Manager isn't enabled for this account.", (
            f"unexpected CapacityManager.Disabled message: {exc.response['Error']['Message']!r}"
        )
    else:
        assert attrs["CapacityManagerStatus"] == "disabled", (
            f"expected CapacityManagerStatus disabled, got {attrs.get('CapacityManagerStatus')}"
        )


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that
    SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must not read as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
