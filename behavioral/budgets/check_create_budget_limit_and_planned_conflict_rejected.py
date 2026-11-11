"""create-budget-limit-and-planned-conflict-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-budget-limit-and-planned-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["budgets"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateBudget rejects a Budget that sets both BudgetLimit and PlannedBudgetLimits (mutually exclusive)."""
    budgets = ctx.client("budgets")
    account_id = _account_id(ctx)
    name = ctx.unique_name("sim2real-budget-conflict-")
    epoch_key = str(int(time.time()))

    error = _error(
        lambda: budgets.create_budget(
            AccountId=account_id,
            Budget={
                "BudgetName": name,
                "BudgetLimit": {"Amount": "100.0", "Unit": "USD"},
                "PlannedBudgetLimits": {epoch_key: {"Amount": "100.0", "Unit": "USD"}},
                "TimeUnit": "MONTHLY",
                "BudgetType": "COST",
            },
        )
    )
    assert error["Code"] == "InvalidParameterException", (
        f"expected InvalidParameterException for a Budget with both BudgetLimit and "
        f"PlannedBudgetLimits set, got {error['Code']!r}"
    )
    expected_message = (
        "Unable to create/update budget - please provide only one of the followings: "
        "Budget Limit/ Planned Budget Limit/ Auto Adjust Data"
    )
    assert error.get("Message") == expected_message, f"expected {expected_message!r}, got {error.get('Message')!r}"

    # Effect absent: the budget was never created.
    not_found = _error(lambda: budgets.describe_budget(AccountId=account_id, BudgetName=name))
    assert not_found["Code"] == "NotFoundException", (
        f"the rejected budget {name!r} must not exist, got describe_budget code {not_found['Code']!r}"
    )
    not_found_message = f"Unable to get budget: {name} - the budget doesn't exist."
    assert not_found.get("Message") == not_found_message, (
        f"expected {not_found_message!r}, got {not_found.get('Message')!r}"
    )

    # Positive control: a budget using only BudgetLimit (no PlannedBudgetLimits) succeeds.
    control_name = ctx.unique_name("sim2real-budget-conflict-control-")
    budgets.create_budget(
        AccountId=account_id,
        Budget={
            "BudgetName": control_name,
            "BudgetLimit": {"Amount": "100.0", "Unit": "USD"},
            "TimeUnit": "MONTHLY",
            "BudgetType": "COST",
        },
    )
    ctx.on_cleanup(lambda: budgets.delete_budget(AccountId=account_id, BudgetName=control_name))
    described = budgets.describe_budget(AccountId=account_id, BudgetName=control_name)["Budget"]
    assert described["BudgetName"] == control_name, (
        f"positive control budget {control_name!r} did not round-trip through describe_budget: {described!r}"
    )


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _error(fn):
    """Call fn(); return its ClientError's Error dict. An unexpected SUCCESS raises, because a
    target ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
