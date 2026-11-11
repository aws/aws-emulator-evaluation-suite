"""create-describe-budget-fields-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-describe-budget-fields-roundtrip"
GROUP = "state"
SERVICES = ["budgets"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateBudget persists BudgetType/TimeUnit/BudgetLimit exactly and DescribeBudget echoes them back."""
    budgets = ctx.client("budgets")
    account_id = _account_id(ctx)
    name = ctx.unique_name("sim2real-budget-")
    budgets.create_budget(
        AccountId=account_id,
        Budget={
            "BudgetName": name,
            "BudgetLimit": {"Amount": "100.0", "Unit": "USD"},
            "TimeUnit": "MONTHLY",
            "BudgetType": "COST",
        },
    )
    ctx.on_cleanup(lambda: budgets.delete_budget(AccountId=account_id, BudgetName=name))

    described = budgets.describe_budget(AccountId=account_id, BudgetName=name)["Budget"]
    assert described["BudgetName"] == name, f"expected BudgetName {name!r}, got {described['BudgetName']!r}"
    assert described["BudgetType"] == "COST", f"expected BudgetType COST, got {described['BudgetType']!r}"
    assert described["TimeUnit"] == "MONTHLY", f"expected TimeUnit MONTHLY, got {described['TimeUnit']!r}"
    assert float(described["BudgetLimit"]["Amount"]) == 100.0, (
        f"expected BudgetLimit.Amount 100.0, got {described['BudgetLimit']['Amount']!r}"
    )
    assert described["BudgetLimit"]["Unit"] == "USD", f"expected BudgetLimit.Unit USD, got {described['BudgetLimit']['Unit']!r}"


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
