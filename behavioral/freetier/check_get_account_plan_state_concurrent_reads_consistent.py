"""get-account-plan-state-concurrent-reads-consistent."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-account-plan-state-concurrent-reads-consistent"
GROUP = "concurrency"
SERVICES = ["freetier"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent GetAccountPlanState calls all agree: every one returns the same accountId, plan type and status,
    or every one fails with ResourceNotFoundException "Missing data for account: <id>"."""
    freetier = ctx.client("freetier")

    def _call(_):
        try:
            r = freetier.get_account_plan_state()
            return ("ok", r["accountId"], r["accountPlanType"], r["accountPlanStatus"])
        except ClientError as e:
            return ("error", e.response["Error"]["Code"], e.response["Error"].get("Message", ""))

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_call, range(8)))

    outcomes = {r[0] for r in results}
    assert len(outcomes) == 1, f"racers disagree on ok-vs-error for GetAccountPlanState: {results}"

    if results[0][0] == "error":
        codes = {r[1] for r in results}
        assert codes == {"ResourceNotFoundException"}, (
            f"expected every racer to see ResourceNotFoundException, got {codes}"
        )
        messages = {r[2] for r in results}
        assert len(messages) == 1, f"racers saw different messages: {messages}"
        message = messages.pop()
        expected = f"Missing data for account: {ctx.account}"
        assert message == expected, f"expected {expected!r}, got {message!r}"
        return

    account_ids = {r[1] for r in results}
    plan_types = {r[2] for r in results}
    plan_statuses = {r[3] for r in results}

    assert len(account_ids) == 1, f"racers observed different accountId values: {account_ids}"
    assert len(plan_types) == 1, f"racers observed different accountPlanType values: {plan_types}"
    assert len(plan_statuses) == 1, (
        f"racers observed different accountPlanStatus values: {plan_statuses}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
