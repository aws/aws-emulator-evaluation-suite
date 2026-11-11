"""create-budget-invalid-time-period-rejected."""
from __future__ import annotations

import datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-budget-invalid-time-period-rejected"
GROUP = "overly-permissive"
SERVICES = ["budgets"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateBudget with TimePeriod.End before TimePeriod.Start is rejected and never creates the budget."""
    budgets = ctx.client("budgets")
    account_id = _account_id(ctx)
    name = ctx.unique_name("sim2real-budget-badperiod-")

    error = _client_error(
        lambda: budgets.create_budget(
            AccountId=account_id,
            Budget={
                "BudgetName": name,
                "BudgetLimit": {"Amount": "50.0", "Unit": "USD"},
                "TimeUnit": "MONTHLY",
                "BudgetType": "COST",
                "TimePeriod": {
                    "Start": datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc),
                    "End": datetime.datetime(2029, 1, 1, tzinfo=datetime.timezone.utc),
                },
            },
        )
    )
    assert error["Code"] == "InvalidParameterException", f"expected InvalidParameterException, got {error['Code']!r}"
    expected_message = "Unable to create/update budget - end time has to be after start time."
    assert error.get("Message") == expected_message, f"expected {expected_message!r}, got {error.get('Message')!r}"

    # Effect absent: the budget was never created.
    not_found = _client_error(lambda: budgets.describe_budget(AccountId=account_id, BudgetName=name))
    assert not_found["Code"] == "NotFoundException", f"expected NotFoundException, got {not_found['Code']!r}"
    not_found_message = f"Unable to get budget: {name} - the budget doesn't exist."
    assert not_found.get("Message") == not_found_message, (
        f"expected {not_found_message!r}, got {not_found.get('Message')!r}"
    )

    # Positive control: a budget with a well-ordered TimePeriod succeeds.
    control_name = ctx.unique_name("sim2real-budget-goodperiod-")
    budgets.create_budget(
        AccountId=account_id,
        Budget={
            "BudgetName": control_name,
            "BudgetLimit": {"Amount": "50.0", "Unit": "USD"},
            "TimeUnit": "MONTHLY",
            "BudgetType": "COST",
            "TimePeriod": {
                "Start": datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
                "End": datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc),
            },
        },
        ResourceTags=[{"Key": "sim2real-env", "Value": "behavioral-test"}],
    )
    ctx.on_cleanup(lambda: budgets.delete_budget(AccountId=account_id, BudgetName=control_name))
    described = budgets.describe_budget(AccountId=account_id, BudgetName=control_name)["Budget"]
    assert described["BudgetName"] == control_name, f"expected {control_name!r}, got {described.get('BudgetName')!r}"


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


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
