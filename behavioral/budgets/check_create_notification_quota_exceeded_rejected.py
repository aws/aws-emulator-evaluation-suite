"""create-notification-quota-exceeded-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-notification-quota-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["budgets"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateNotification rejects the 11th notification on a budget (documented cap of 10 per budget)."""
    budgets = ctx.client("budgets")
    account_id = _account_id(ctx)
    name = ctx.unique_name("sim2real-budget-notifquota-")
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

    subscribers = [{"SubscriptionType": "EMAIL", "Address": "sim2real-budgets-notifquota@example.com"}]
    for threshold in range(10, 101, 10):  # 10 distinct notifications: thresholds 10..100
        budgets.create_notification(
            AccountId=account_id,
            BudgetName=name,
            Notification={
                "NotificationType": "ACTUAL",
                "ComparisonOperator": "GREATER_THAN",
                "Threshold": float(threshold),
                "ThresholdType": "PERCENTAGE",
            },
            Subscribers=subscribers,
        )

    error = _error(
        lambda: budgets.create_notification(
            AccountId=account_id,
            BudgetName=name,
            Notification={
                "NotificationType": "ACTUAL",
                "ComparisonOperator": "GREATER_THAN",
                "Threshold": 110.0,
                "ThresholdType": "PERCENTAGE",
            },
            Subscribers=subscribers,
        )
    )
    assert error["Code"] == "CreationLimitExceededException", (
        f"expected CreationLimitExceededException, got {error['Code']!r}"
    )
    expected_message = "Unable to create notification - one budget can only have 10 notifications"
    assert error.get("Message") == expected_message, f"expected {expected_message!r}, got {error.get('Message')!r}"

    # Effect absent: still exactly 10 notifications, the 11th never got created.
    notifications = budgets.describe_notifications_for_budget(AccountId=account_id, BudgetName=name)[
        "Notifications"
    ]
    thresholds = {n["Threshold"] for n in notifications}
    assert len(notifications) == 10, f"expected 10 notifications after rejected 11th, got {len(notifications)}"
    assert 110.0 not in thresholds, f"expected 110.0 absent after rejected create, got {thresholds}"

    # Restore: the limit is a live count, not a blanket lock — freeing one slot by deleting an
    # existing notification lets the identical, previously-rejected call succeed.
    freed_threshold = 100.0
    budgets.delete_notification(
        AccountId=account_id,
        BudgetName=name,
        Notification={
            "NotificationType": "ACTUAL",
            "ComparisonOperator": "GREATER_THAN",
            "Threshold": freed_threshold,
            "ThresholdType": "PERCENTAGE",
        },
    )
    budgets.create_notification(
        AccountId=account_id,
        BudgetName=name,
        Notification={
            "NotificationType": "ACTUAL",
            "ComparisonOperator": "GREATER_THAN",
            "Threshold": 110.0,
            "ThresholdType": "PERCENTAGE",
        },
        Subscribers=subscribers,
    )
    restored = budgets.describe_notifications_for_budget(AccountId=account_id, BudgetName=name)["Notifications"]
    restored_thresholds = {n["Threshold"] for n in restored}
    assert len(restored) == 10, f"expected 10 notifications after restore, got {len(restored)}"
    assert 110.0 in restored_thresholds, f"expected 110.0 present after restore, got {restored_thresholds}"
    assert freed_threshold not in restored_thresholds, (
        f"expected {freed_threshold} gone after delete, got {restored_thresholds}"
    )

    # Positive control: adding another subscriber to an existing notification still works.
    budgets.create_subscriber(
        AccountId=account_id,
        BudgetName=name,
        Notification={
            "NotificationType": "ACTUAL",
            "ComparisonOperator": "GREATER_THAN",
            "Threshold": 10.0,
            "ThresholdType": "PERCENTAGE",
        },
        Subscriber={"SubscriptionType": "EMAIL", "Address": "sim2real-budgets-notifquota-2@example.com"},
    )
    subs = budgets.describe_subscribers_for_notification(
        AccountId=account_id,
        BudgetName=name,
        Notification={
            "NotificationType": "ACTUAL",
            "ComparisonOperator": "GREATER_THAN",
            "Threshold": 10.0,
            "ThresholdType": "PERCENTAGE",
        },
    )["Subscribers"]
    assert len(subs) == 2, f"expected 2 subscribers on the existing notification, got {len(subs)}"


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _error(fn):
    """Call fn(); return its ClientError's Error dict; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
