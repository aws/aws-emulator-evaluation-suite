"""update-budget-persists-new-limit."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-budget-persists-new-limit"
GROUP = "state"
SERVICES = ["budgets"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateBudget overwrites BudgetLimit with the NewBudget value and refreshes LastUpdatedTime."""
    budgets = ctx.client("budgets")
    account_id = _account_id(ctx)
    name = ctx.unique_name("sim2real-budget-upd-")
    base_budget = {
        "BudgetName": name,
        "BudgetLimit": {"Amount": "100.0", "Unit": "USD"},
        "TimeUnit": "MONTHLY",
        "BudgetType": "COST",
    }
    budgets.create_budget(AccountId=account_id, Budget=base_budget)
    ctx.on_cleanup(lambda: budgets.delete_budget(AccountId=account_id, BudgetName=name))

    before = budgets.describe_budget(AccountId=account_id, BudgetName=name)["Budget"]
    before_updated = before["LastUpdatedTime"]

    new_budget = dict(base_budget)
    new_budget["BudgetLimit"] = {"Amount": "250.0", "Unit": "USD"}
    budgets.update_budget(AccountId=account_id, NewBudget=new_budget)

    # Budgets' LastUpdatedTime has 1-second resolution, so the update can land in
    # the same clock second as the create; poll (bounded) until it visibly advances.
    deadline = time.time() + 10
    while True:
        described = budgets.describe_budget(AccountId=account_id, BudgetName=name)["Budget"]
        after_updated = described["LastUpdatedTime"]
        if after_updated > before_updated or time.time() >= deadline:
            break
        time.sleep(0.5)

    assert after_updated > before_updated, (
        f"expected LastUpdatedTime to advance past {before_updated!r} within 10s of "
        f"UpdateBudget, still {after_updated!r}"
    )
    amount = float(described["BudgetLimit"]["Amount"])
    assert amount == 250.0, f"expected BudgetLimit.Amount 250.0 after UpdateBudget, got {amount}"


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
