"""upgrade-account-plan-invalid-type-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "upgrade-account-plan-invalid-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["freetier"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpgradeAccountPlan(PREMIUM) is rejected with ValidationException and the exact enum-constraint message,
    and GetAccountPlanState gives the same answer before and after the call: the same plan type and
    status, or ResourceNotFoundException both times for an account with no Free Tier plan.
    """
    freetier = ctx.client("freetier")

    before = _plan_state(freetier)

    code, message = _error(lambda: freetier.upgrade_account_plan(accountPlanType="PREMIUM"))
    assert code == "ValidationException", code
    assert message == (
        "1 validation error detected: Value 'PREMIUM' at 'accountPlanType' failed to satisfy "
        "constraint: Member must satisfy enum value set: [PAID, FREE]"
    ), message

    after = _plan_state(freetier)
    assert after == before, (
        f"GetAccountPlanState answered {before!r} before and {after!r} after a rejected "
        f"UpgradeAccountPlan call"
    )


def _plan_state(freetier):
    """(accountPlanType, accountPlanStatus), or ("ResourceNotFoundException",) for an account that
    has no Free Tier plan."""
    try:
        state = freetier.get_account_plan_state()
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return ("ResourceNotFoundException",)
        raise
    return (state["accountPlanType"], state["accountPlanStatus"])


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an emulator
    ACCEPTING an input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(
        f"real AWS rejects accountPlanType='PREMIUM' with ValidationException, but it "
        f"SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
