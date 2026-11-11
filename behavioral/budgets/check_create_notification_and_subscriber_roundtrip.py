"""create-notification-and-subscriber-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-notification-and-subscriber-roundtrip"
GROUP = "state"
SERVICES = ["budgets"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateNotification + CreateSubscriber persist exact field values, echoed by the Describe* list ops."""
    budgets = ctx.client("budgets")
    account_id = _account_id(ctx)
    name = ctx.unique_name("sim2real-budget-notif-")
    budgets.create_budget(
        AccountId=account_id,
        Budget={
            "BudgetName": name,
            "BudgetLimit": {"Amount": "50.0", "Unit": "USD"},
            "TimeUnit": "MONTHLY",
            "BudgetType": "COST",
        },
        ResourceTags=[{"Key": "sim2real-env", "Value": "behavioral-test"}],
    )
    ctx.on_cleanup(lambda: budgets.delete_budget(AccountId=account_id, BudgetName=name))

    notification = {
        "NotificationType": "FORECASTED",
        "ComparisonOperator": "GREATER_THAN",
        "Threshold": 75.0,
        "ThresholdType": "PERCENTAGE",
    }
    budgets.create_notification(
        AccountId=account_id,
        BudgetName=name,
        Notification=notification,
        Subscribers=[{"SubscriptionType": "EMAIL", "Address": "sim2real-budgets-roundtrip-a@example.com"}],
    )
    budgets.create_subscriber(
        AccountId=account_id,
        BudgetName=name,
        Notification=notification,
        Subscriber={"SubscriptionType": "EMAIL", "Address": "sim2real-budgets-roundtrip-b@example.com"},
    )

    notifications = budgets.describe_notifications_for_budget(AccountId=account_id, BudgetName=name)[
        "Notifications"
    ]
    assert len(notifications) == 1, f"expected exactly 1 notification, got {len(notifications)}: {notifications}"
    got = notifications[0]
    assert got["NotificationType"] == "FORECASTED", (
        f"expected NotificationType FORECASTED, got {got['NotificationType']}"
    )
    assert got["ComparisonOperator"] == "GREATER_THAN", (
        f"expected ComparisonOperator GREATER_THAN, got {got['ComparisonOperator']}"
    )
    assert got["Threshold"] == 75.0, f"expected Threshold 75.0, got {got['Threshold']}"
    # PERCENTAGE is the ThresholdType default; some API responses omit the field
    # entirely when it equals the default rather than echoing it explicitly.
    assert got.get("ThresholdType", "PERCENTAGE") == "PERCENTAGE", (
        f"expected ThresholdType PERCENTAGE (or omitted), got {got.get('ThresholdType')!r}"
    )

    subscribers = budgets.describe_subscribers_for_notification(
        AccountId=account_id, BudgetName=name, Notification=notification
    )["Subscribers"]
    addresses = {s["Address"] for s in subscribers}
    expected_addresses = {
        "sim2real-budgets-roundtrip-a@example.com",
        "sim2real-budgets-roundtrip-b@example.com",
    }
    assert addresses == expected_addresses, f"expected subscriber addresses {expected_addresses}, got {addresses}"
    non_email = [s for s in subscribers if s["SubscriptionType"] != "EMAIL"]
    assert not non_email, f"expected all subscribers to be EMAIL, got non-EMAIL entries: {non_email}"


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
