"""get-account-plan-state-matches-caller-account-id."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-account-plan-state-matches-caller-account-id"
GROUP = "state"
SERVICES = ["freetier"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The accountId in GetAccountPlanState matches the caller's real account, per STS -- whether
    that surfaces in a successful response's accountId field, or in the ResourceNotFoundException
    message for an account with no Free Tier plan record provisioned yet."""
    freetier = ctx.client("freetier")
    sts = ctx.client("sts")
    identity = sts.get_caller_identity()

    try:
        plan = freetier.get_account_plan_state()
    except ClientError as err:
        error = err.response["Error"]
        assert error["Code"] == "ResourceNotFoundException", error
        assert error["Message"] == f"Missing data for account: {identity['Account']}", error
        return

    assert plan["accountId"] == identity["Account"], (
        f"freetier accountId {plan['accountId']!r} != caller account {identity['Account']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

