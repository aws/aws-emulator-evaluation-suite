"""delete-notification-cascades-subscribers."""
from __future__ import annotations

import time


from behavioral_harness import tags

CHECK = "delete-notification-cascades-subscribers"
GROUP = "state"
SERVICES = ["budgets"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteNotification also deletes all subscribers attached to it (documented cascade)."""
    budgets = ctx.client("budgets")
    account_id = _account_id(ctx)
    name = ctx.unique_name("sim2real-budget-notcasc-")
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
        "Threshold": 80.0,
        "ThresholdType": "PERCENTAGE",
    }
    budgets.create_notification(
        AccountId=account_id,
        BudgetName=name,
        Notification=notification,
        Subscribers=[{"SubscriptionType": "EMAIL", "Address": "sim2real-budgets-notcasc@example.com"}],
    )

    budgets.delete_notification(AccountId=account_id, BudgetName=name, Notification=notification)

    # Allow a short bounded window for the deletion to become visible to Describe*.
    # The primary, documented signal is that the notification disappears from the
    # budget's notification list (DeleteNotification cascades to its subscribers too).
    deadline = time.monotonic() + 30.0
    remaining = None
    while time.monotonic() < deadline:
        remaining = budgets.describe_notifications_for_budget(AccountId=account_id, BudgetName=name)[
            "Notifications"
        ]
        if remaining == []:
            break
        time.sleep(2)
    assert remaining == [], f"expected notification to be gone, still present: {remaining!r}"

    # Secondary check: real AWS answers DescribeSubscribersForNotification on the deleted
    # notification with a 200 that carries no "Subscribers" key, never a NotFoundException.
    # A 200 that still carries the original subscriber means the cascade never happened.
    resp = budgets.describe_subscribers_for_notification(
        AccountId=account_id, BudgetName=name, Notification=notification
    )
    subs = resp.get("Subscribers", [])
    assert subs == [], f"expected no subscribers after cascade delete, still present: {subs!r}"


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
