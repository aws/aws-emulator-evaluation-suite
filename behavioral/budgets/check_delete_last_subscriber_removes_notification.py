"""delete-last-subscriber-removes-notification."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-last-subscriber-removes-notification"
GROUP = "state"
SERVICES = ["budgets"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Deleting the last subscriber of a notification also deletes the notification itself (documented)."""
    budgets = ctx.client("budgets")
    account_id = _account_id(ctx)
    name = ctx.unique_name("sim2real-budget-lastsub-")
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
    subscriber = {"SubscriptionType": "EMAIL", "Address": "sim2real-budgets-lastsub@example.com"}
    budgets.create_notification(
        AccountId=account_id, BudgetName=name, Notification=notification, Subscribers=[subscriber]
    )

    budgets.delete_subscriber(
        AccountId=account_id, BudgetName=name, Notification=notification, Subscriber=subscriber
    )

    # The notification had exactly one subscriber, so removing it removes the notification too.
    # Primary, documented signal: the notification disappears from the budget's list.
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

    # Secondary check: listing subscribers for the now-deleted notification succeeds and
    # reports none -- never the deleted subscriber. Real AWS answers 200 and omits the
    # "Subscribers" key entirely rather than returning an empty list, so absence-of-key
    # means "none" here.
    remaining_subscribers = budgets.describe_subscribers_for_notification(
        AccountId=account_id, BudgetName=name, Notification=notification
    ).get("Subscribers", [])
    assert remaining_subscribers == [], (
        f"expected no subscribers for the deleted notification, still present: {remaining_subscribers!r}"
    )


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
