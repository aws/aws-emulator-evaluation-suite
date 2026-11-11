"""delete-budget-removes-resource."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-budget-removes-resource"
GROUP = "state"
SERVICES = ["budgets"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteBudget permanently removes the budget: a subsequent DescribeBudget returns
    NotFoundException, an UpdateBudget on the dead name also fails with NotFoundException,
    and the name is reusable by a fresh CreateBudget."""
    budgets = ctx.client("budgets")
    account_id = _account_id(ctx)
    name = ctx.unique_name("sim2real-budget-del-")
    _create_budget(budgets, account_id, name, "50.0")

    budgets.delete_budget(AccountId=account_id, BudgetName=name)

    gone_message = f"Unable to get budget: {name} - the budget doesn't exist."
    error = _client_error(lambda: budgets.describe_budget(AccountId=account_id, BudgetName=name))
    assert error["Code"] == "NotFoundException", (
        f"DescribeBudget on a deleted budget: expected NotFoundException, got {error['Code']!r}"
    )
    assert error.get("Message") == gone_message, f"expected {gone_message!r}, got {error.get('Message')!r}"

    update_error = _client_error(
        lambda: budgets.update_budget(
            AccountId=account_id,
            NewBudget={
                "BudgetName": name,
                "BudgetLimit": {"Amount": "75.0", "Unit": "USD"},
                "TimeUnit": "MONTHLY",
                "BudgetType": "COST",
            },
        )
    )
    assert update_error["Code"] == "NotFoundException", (
        f"UpdateBudget on a deleted budget: expected NotFoundException, got {update_error['Code']!r}"
    )
    assert update_error.get("Message") == gone_message, (
        f"expected {gone_message!r}, got {update_error.get('Message')!r}"
    )

    _create_budget(budgets, account_id, name, "50.0")
    ctx.on_cleanup(lambda: budgets.delete_budget(AccountId=account_id, BudgetName=name))
    reused = budgets.describe_budget(AccountId=account_id, BudgetName=name)
    assert reused["Budget"]["BudgetName"] == name, (
        f"the deleted budget name must be reusable by a fresh CreateBudget, got {reused['Budget']!r}"
    )


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_budget(budgets, account_id, name, amount):
    budgets.create_budget(
        AccountId=account_id,
        Budget={
            "BudgetName": name,
            "BudgetLimit": {"Amount": amount, "Unit": "USD"},
            "TimeUnit": "MONTHLY",
            "BudgetType": "COST",
        },
    )


def _client_error(fn):
    """Call fn(); return the ClientError's Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
