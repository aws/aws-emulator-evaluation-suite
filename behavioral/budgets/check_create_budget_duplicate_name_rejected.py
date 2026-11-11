"""create-budget-duplicate-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-budget-duplicate-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["budgets"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateBudget with an already-used BudgetName is rejected and does not overwrite the original
    budget; once the original is gone, the identical call succeeds."""
    budgets = ctx.client("budgets")
    account_id = _account_id(ctx)
    name = ctx.unique_name("sim2real-budget-dup-")
    duplicate_budget = {
        "BudgetName": name,
        "BudgetLimit": {"Amount": "999.0", "Unit": "USD"},
        "TimeUnit": "MONTHLY",
        "BudgetType": "COST",
    }

    # Positive control: BudgetName is free, so the original create succeeds.
    budgets.create_budget(
        AccountId=account_id,
        Budget={
            "BudgetName": name,
            "BudgetLimit": {"Amount": "100.0", "Unit": "USD"},
            "TimeUnit": "MONTHLY",
            "BudgetType": "COST",
        },
    )
    ctx.on_cleanup(lambda: _safe_delete(budgets, account_id, name))

    # Break exactly one thing: reuse the same BudgetName for a second create.
    error = _client_error(lambda: budgets.create_budget(AccountId=account_id, Budget=duplicate_budget))
    assert error["Code"] == "DuplicateRecordException", f"expected DuplicateRecordException, got {error['Code']!r}"
    expected_message = f"Error creating budget: {name} - the budget already exists."
    assert error.get("Message") == expected_message, f"expected {expected_message!r}, got {error.get('Message')!r}"

    # Effect absent: the original budget's limit was not overwritten by the rejected duplicate.
    described = budgets.describe_budget(AccountId=account_id, BudgetName=name)["Budget"]
    original_amount = float(described["BudgetLimit"]["Amount"])
    assert original_amount == 100.0, f"expected original limit 100.0 to survive the rejected duplicate, got {original_amount}"

    # Restore: remove the original so the name is free again.
    budgets.delete_budget(AccountId=account_id, BudgetName=name)
    gone = _client_error(lambda: budgets.describe_budget(AccountId=account_id, BudgetName=name))
    assert gone["Code"] == "NotFoundException", f"expected NotFoundException after delete, got {gone['Code']!r}"
    gone_message = f"Unable to get budget: {name} - the budget doesn't exist."
    assert gone.get("Message") == gone_message, f"expected {gone_message!r}, got {gone.get('Message')!r}"

    # The identical call that was rejected moments ago now succeeds, because the name is free.
    budgets.create_budget(AccountId=account_id, Budget=duplicate_budget)
    restored = budgets.describe_budget(AccountId=account_id, BudgetName=name)["Budget"]
    restored_amount = float(restored["BudgetLimit"]["Amount"])
    assert restored_amount == 999.0, f"expected the restored create to take limit 999.0, got {restored_amount}"


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _client_error(fn):
    """Call fn(); return the ClientError's Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_delete(budgets, account_id, name):
    try:
        budgets.delete_budget(AccountId=account_id, BudgetName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
