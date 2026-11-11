"""concurrent-get-account-plan-state-consistent."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-get-account-plan-state-consistent"
GROUP = "concurrency"
SERVICES = ["freetier"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent GetAccountPlanState calls all agree: either every one succeeds with the same accountId, plan type
    and status, or every one fails with ResourceNotFoundException "Missing data for account: <id>"."""
    freetier = ctx.client("freetier")

    def _call(_):
        try:
            r = freetier.get_account_plan_state()
            return ("ok", r["accountId"], r["accountPlanType"], r["accountPlanStatus"])
        except ClientError as err:
            return ("error", err.response["Error"]["Code"], err.response["Error"].get("Message", ""))

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_call, range(8)))

    assert len({r[0] for r in results}) == 1, results  # all racers agree ok-vs-error

    if results[0][0] == "ok":
        account_ids = {r[1] for r in results}
        plan_types = {r[2] for r in results}
        plan_statuses = {r[3] for r in results}
        assert len(account_ids) == 1, account_ids
        assert len(plan_types) == 1, plan_types
        assert len(plan_statuses) == 1, plan_statuses
    else:
        codes = {r[1] for r in results}
        assert codes == {"ResourceNotFoundException"}, codes
        messages = {r[2] for r in results}
        assert len(messages) == 1, messages
        expected = f"Missing data for account: {ctx.account}"
        assert messages == {expected}, (messages, expected)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

