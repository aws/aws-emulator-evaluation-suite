"""op-contract-update-capacity-manager-organizations-access."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-update-capacity-manager-organizations-access"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-capacity-manager")
def run(ctx) -> None:
    """UpdateCapacityManagerOrganizationsAccess, from an account that is not an Organizations management
    account, fails with DryRunOperation under DryRun, with OrganizationTrustedAccessDisabled for True and
    with InvalidParameterValue for False (exact messages); OrganizationsAccess stays false."""
    ec2 = ctx.client("ec2")
    from botocore.exceptions import ClientError

    try:
        enabled = ec2.get_capacity_manager_attributes()["CapacityManagerStatus"] == "enabled"
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "CapacityManager.Disabled":
            raise
        enabled = False

    if not enabled:
        # Create-or-adopt: EnableCapacityManager is a real API, not console-only -- so
        # turn it on ourselves and clean up only what we turned on.
        ec2.enable_capacity_manager(OrganizationsAccess=False)
        ctx.on_cleanup(lambda: _best_effort_disable(ec2))

    # Positive control: the account and credentials are healthy for this service --
    # OrganizationsAccess starts at its documented default, confirmed by an
    # independent read, not by assuming EnableCapacityManager's own echo.
    baseline = ec2.get_capacity_manager_attributes()
    assert baseline["OrganizationsAccess"] is False, (
        f"expected OrganizationsAccess=False as the freshly-enabled default, got "
        f"{baseline['OrganizationsAccess']!r}"
    )

    # DryRun short-circuits with DryRunOperation ahead of the entitlement check below.
    code, message = _error(
        lambda: ec2.update_capacity_manager_organizations_access(
            OrganizationsAccess=True, DryRun=True
        )
    )
    assert (code, message) == ("DryRunOperation", _DRY_RUN_MESSAGE), (
        f"expected DryRunOperation {_DRY_RUN_MESSAGE!r}, got {code!r} {message!r}"
    )

    # Refusal #1: turning Organizations access ON needs an Organizations
    # management/delegated-administrator account. An organization member account never
    # is one, so this is a permanent per-account entitlement gate, not a flake --
    # the refusal itself is the contract being asserted.
    code, message = _error(
        lambda: ec2.update_capacity_manager_organizations_access(OrganizationsAccess=True)
    )
    expected = (
        "CapacityManager.OrganizationTrustedAccessDisabled",
        "This account can't access Capacity Manager with AWS Organizations. "
        "Enable trusted access or use account mode.",
    )
    assert (code, message) == expected, f"expected {expected!r}, got {(code, message)!r}"

    # Effect-absent: the refused attempt above did not flip the setting, confirmed by
    # an independent read.
    after_denied_enable = ec2.get_capacity_manager_attributes()
    assert after_denied_enable["OrganizationsAccess"] is False, (
        "the denied OrganizationsAccess=True call should not have mutated the setting"
    )

    # Refusal #2: distinct error boundary -- turning it OFF when it was never ON is an
    # always-invalid input at this state (no restore leg by construction: it can never
    # become valid without first getting Organizations access on, which refusal #1
    # shows this account can never do).
    code, message = _error(
        lambda: ec2.update_capacity_manager_organizations_access(OrganizationsAccess=False)
    )
    expected = ("InvalidParameterValue", "Capacity Manager doesn't have organizations access enabled.")
    assert (code, message) == expected, f"expected {expected!r}, got {(code, message)!r}"


def _best_effort_disable(ec2) -> None:
    ec2.disable_capacity_manager()


def _error(fn: Callable[[], Any]):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected a ClientError, but the call SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
