"""update-subscriber-changes-address."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-subscriber-changes-address"
GROUP = "state"
SERVICES = ["budgets"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSubscriber replaces the old subscriber address with the new one; the old address is gone."""
    budgets = ctx.client("budgets")
    account_id = _account_id(ctx)
    name = ctx.unique_name("sim2real-budget-updsub-")
    budgets.create_budget(
        AccountId=account_id,
        Budget={
            "BudgetName": name,
            "BudgetLimit": {"Amount": "50.0", "Unit": "USD"},
            "TimeUnit": "MONTHLY",
            "BudgetType": "COST",
        },
    )
    ctx.on_cleanup(lambda: budgets.delete_budget(AccountId=account_id, BudgetName=name))

    notification = {
        "NotificationType": "ACTUAL",
        "ComparisonOperator": "GREATER_THAN",
        "Threshold": 60.0,
        "ThresholdType": "PERCENTAGE",
    }
    old_subscriber = {"SubscriptionType": "EMAIL", "Address": "sim2real-budgets-old@example.com"}
    new_subscriber = {"SubscriptionType": "EMAIL", "Address": "sim2real-budgets-new@example.com"}
    budgets.create_notification(
        AccountId=account_id, BudgetName=name, Notification=notification, Subscribers=[old_subscriber]
    )

    budgets.update_subscriber(
        AccountId=account_id,
        BudgetName=name,
        Notification=notification,
        OldSubscriber=old_subscriber,
        NewSubscriber=new_subscriber,
    )

    subscribers = budgets.describe_subscribers_for_notification(
        AccountId=account_id, BudgetName=name, Notification=notification
    )["Subscribers"]
    addresses = {s["Address"] for s in subscribers}
    assert addresses == {"sim2real-budgets-new@example.com"}, (
        f"expected only the new address after UpdateSubscriber, got {addresses}"
    )
    assert "sim2real-budgets-old@example.com" not in addresses, (
        f"old address should have been replaced, still present in {addresses}"
    )


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
