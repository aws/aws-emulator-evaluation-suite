"""describe-budget-notifications-for-account-lists-across-budgets."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-budget-notifications-for-account-lists-across-budgets"
GROUP = "state"
SERVICES = ["budgets"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeBudgetNotificationsForAccount lists notifications across distinct budgets, each
    correctly attributed to its own BudgetName rather than conflated with the other."""
    budgets = ctx.client("budgets")
    account_id = _account_id(ctx)
    name_a = ctx.unique_name("sim2real-budget-acctnotif-a-")
    name_b = ctx.unique_name("sim2real-budget-acctnotif-b-")
    threshold_a = 65.0
    threshold_b = 42.0

    for name in (name_a, name_b):
        budgets.create_budget(
            AccountId=account_id,
            Budget={
                "BudgetName": name,
                "BudgetLimit": {"Amount": "50.0", "Unit": "USD"},
                "TimeUnit": "MONTHLY",
                "BudgetType": "COST",
            },
        )
        ctx.on_cleanup(lambda name=name: budgets.delete_budget(AccountId=account_id, BudgetName=name))

    for name, threshold in ((name_a, threshold_a), (name_b, threshold_b)):
        budgets.create_notification(
            AccountId=account_id,
            BudgetName=name,
            Notification={
                "NotificationType": "ACTUAL",
                "ComparisonOperator": "GREATER_THAN",
                "Threshold": threshold,
                "ThresholdType": "PERCENTAGE",
            },
            Subscribers=[{"SubscriptionType": "EMAIL", "Address": "sim2real-budgets-acctnotif@example.com"}],
        )

    found = {}
    next_token = None
    for _ in range(50):
        kwargs = {"AccountId": account_id}
        if next_token:
            kwargs["NextToken"] = next_token
        page = budgets.describe_budget_notifications_for_account(**kwargs)
        for entry in page["BudgetNotificationsForAccount"]:
            if entry["BudgetName"] in (name_a, name_b):
                found[entry["BudgetName"]] = entry
        if name_a in found and name_b in found:
            break
        next_token = page.get("NextToken")
        if not next_token:
            break

    assert name_a in found, f"budget {name_a} was not found via DescribeBudgetNotificationsForAccount"
    assert name_b in found, f"budget {name_b} was not found via DescribeBudgetNotificationsForAccount"

    thresholds_a = {n["Threshold"] for n in found[name_a]["Notifications"]}
    thresholds_b = {n["Threshold"] for n in found[name_b]["Notifications"]}
    assert thresholds_a == {threshold_a}, f"expected {name_a} thresholds == {{{threshold_a}}}, got {thresholds_a}"
    assert thresholds_b == {threshold_b}, f"expected {name_b} thresholds == {{{threshold_b}}}, got {thresholds_b}"


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
