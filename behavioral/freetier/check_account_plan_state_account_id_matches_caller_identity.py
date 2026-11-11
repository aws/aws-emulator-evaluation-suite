"""account-plan-state-account-id-matches-caller-identity."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "account-plan-state-account-id-matches-caller-identity"
GROUP = "consistency"
SERVICES = ["freetier"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAccountPlanState names the caller's STS account: in its accountId when a plan exists, or in
    ResourceNotFoundException "Missing data for account: <id>" when none does."""
    sts = ctx.client("sts")
    caller_account = sts.get_caller_identity()["Account"]

    freetier = ctx.client("freetier")
    try:
        resp = freetier.get_account_plan_state()
    except ClientError as e:
        error = e.response["Error"]
        assert error["Code"] == "ResourceNotFoundException", error
        assert error["Message"] == f"Missing data for account: {caller_account}", error
        return

    assert resp["accountId"] == caller_account, (resp["accountId"], caller_account)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
