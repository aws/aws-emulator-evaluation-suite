"""upgrade-account-plan-invalid-plan-type-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "upgrade-account-plan-invalid-plan-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["freetier"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpgradeAccountPlan(GOLD) is rejected with ValidationException and the exact enum-constraint message,
    and leaves the plan type and status unchanged (an account without a plan record still has none).
    """
    freetier = ctx.client("freetier")

    before = _plan_state_or_none(freetier)

    error = _client_error(lambda: freetier.upgrade_account_plan(accountPlanType="GOLD"))
    assert error["Code"] == "ValidationException", error
    assert error["Message"] == (
        "1 validation error detected: Value 'GOLD' at 'accountPlanType' failed to satisfy "
        "constraint: Member must satisfy enum value set: [PAID, FREE]"
    ), error["Message"]

    # effect absent: the plan type/status is untouched by the rejected request, and an
    # unenrolled account is not enrolled as a side effect of the rejected call either.
    after = _plan_state_or_none(freetier)
    if before is None:
        assert after is None, (
            f"account had no Free Tier plan record before the rejected call, but now reports "
            f"{after!r}"
        )
    else:
        assert after["accountPlanType"] == before["accountPlanType"]
        assert after["accountPlanStatus"] == before["accountPlanStatus"]


def _plan_state_or_none(freetier):
    try:
        return freetier.get_account_plan_state()
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected rejection, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
