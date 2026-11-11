"""delete-notification-removes-only-target."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-notification-removes-only-target"
GROUP = "state"
SERVICES = ["budgets"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteNotification removes exactly the targeted notification and leaves sibling notifications intact."""
    budgets = ctx.client("budgets")
    account_id = _account_id(ctx)
    name = ctx.unique_name("sim2real-budget-surgical-")
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

    keep = {
        "NotificationType": "ACTUAL",
        "ComparisonOperator": "GREATER_THAN",
        "Threshold": 50.0,
        "ThresholdType": "PERCENTAGE",
    }
    remove = {
        "NotificationType": "ACTUAL",
        "ComparisonOperator": "GREATER_THAN",
        "Threshold": 90.0,
        "ThresholdType": "PERCENTAGE",
    }
    subscribers = [{"SubscriptionType": "EMAIL", "Address": "sim2real-budgets-surgical@example.com"}]
    budgets.create_notification(AccountId=account_id, BudgetName=name, Notification=keep, Subscribers=subscribers)
    budgets.create_notification(AccountId=account_id, BudgetName=name, Notification=remove, Subscribers=subscribers)

    budgets.delete_notification(AccountId=account_id, BudgetName=name, Notification=remove)

    # Sibling checks against this same call (DeleteNotification -> DescribeNotificationsForBudget)
    # bound the read in a short retry window rather than trusting a single immediate read; do the
    # same here instead of assuming the deletion is visible on the very next call.
    deadline = time.monotonic() + 30.0
    remaining = None
    while time.monotonic() < deadline:
        remaining = budgets.describe_notifications_for_budget(AccountId=account_id, BudgetName=name)[
            "Notifications"
        ]
        if len(remaining) == 1:
            break
        time.sleep(2)
    thresholds = {n["Threshold"] for n in remaining}
    assert 50.0 in thresholds, f"expected kept notification (threshold 50.0) to survive, got {thresholds!r}"
    assert 90.0 not in thresholds, f"expected removed notification (threshold 90.0) to be gone, got {thresholds!r}"
    assert len(remaining) == 1, f"expected exactly the one surviving notification, got {remaining!r}"


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
