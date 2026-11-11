"""upgrade-account-plan-invalid-plan-type-error."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "upgrade-account-plan-invalid-plan-type-error"
GROUP = "error-semantics"
SERVICES = ["freetier"]


def _client_error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(
        "expected UpgradeAccountPlan(accountPlanType='GOLD') to be rejected with "
        f"ValidationException, but it succeeded and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpgradeAccountPlan(GOLD) is rejected with ValidationException and the exact enum-constraint message,
    and the account's plan state (or its ResourceNotFoundException) reads the same before and after the call.
    """
    freetier = ctx.client("freetier")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    before = _plan_snapshot(freetier, account_id)

    error = _client_error(lambda: freetier.upgrade_account_plan(accountPlanType="GOLD"))
    assert error["Code"] == "ValidationException", f"expected ValidationException, got {error!r}"
    assert error["Message"] == (
        "1 validation error detected: Value 'GOLD' at 'accountPlanType' failed to satisfy "
        "constraint: Member must satisfy enum value set: [PAID, FREE]"
    ), error["Message"]

    after = _plan_snapshot(freetier, account_id)
    assert after == before, (
        f"account plan snapshot changed from {before!r} to {after!r} after a rejected "
        "UpgradeAccountPlan call"
    )


def _plan_snapshot(freetier, account_id):
    """A comparable snapshot of the account's Free Tier plan state: the (type, status) pair, or
    the ResourceNotFoundException marker if the account has no plan record at all -- both are
    real states an account can be in, and either is valid to hold constant across a
    rejected call."""
    try:
        resp = freetier.get_account_plan_state()
    except ClientError as err:
        error = err.response["Error"]
        assert error["Code"] == "ResourceNotFoundException", error
        assert error["Message"] == f"Missing data for account: {account_id}", error["Message"]
        return ("ResourceNotFoundException", None)
    return (resp["accountPlanType"], resp["accountPlanStatus"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
