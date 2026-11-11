"""delete-budget-cascades-notifications-and-subscribers."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-budget-cascades-notifications-and-subscribers"
GROUP = "state"
SERVICES = ["budgets"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting a budget also deletes its notifications and subscribers (documented cascade)."""
    budgets = ctx.client("budgets")
    account_id = _account_id(ctx)
    name = ctx.unique_name("sim2real-budget-casc-")
    budgets.create_budget(
        AccountId=account_id,
        Budget={
            "BudgetName": name,
            "BudgetLimit": {"Amount": "50.0", "Unit": "USD"},
            "TimeUnit": "MONTHLY",
            "BudgetType": "COST",
        },
    )
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
        Subscribers=[{"SubscriptionType": "EMAIL", "Address": "sim2real-budgets-casc@example.com"}],
    )

    # Positive control: the notification and its subscriber exist before the delete,
    # so the post-delete absence below is a cascade, not a check that never wired up.
    pre_notifications = budgets.describe_notifications_for_budget(AccountId=account_id, BudgetName=name)[
        "Notifications"
    ]
    assert len(pre_notifications) == 1, f"expected 1 notification pre-delete, got {pre_notifications!r}"
    pre_subscribers = budgets.describe_subscribers_for_notification(
        AccountId=account_id, BudgetName=name, Notification=notification
    )["Subscribers"]
    assert len(pre_subscribers) == 1, f"expected 1 subscriber pre-delete, got {pre_subscribers!r}"

    budgets.delete_budget(AccountId=account_id, BudgetName=name)

    gone_message = f"Unable to get budget: {name} - the budget doesn't exist."
    error = _client_error(
        lambda: budgets.describe_notifications_for_budget(AccountId=account_id, BudgetName=name)
    )
    assert error["Code"] == "NotFoundException", f"expected NotFoundException for notifications, got {error['Code']!r}"
    assert error.get("Message") == gone_message, f"expected {gone_message!r}, got {error.get('Message')!r}"

    # Real AWS answers this one with 200 + no Subscribers key (never NotFoundException) once
    # the parent budget is gone, rather than raising like describe_notifications_for_budget does.
    subscribers_after = budgets.describe_subscribers_for_notification(
        AccountId=account_id, BudgetName=name, Notification=notification
    ).get("Subscribers", [])
    assert not subscribers_after, f"expected no subscribers post-delete, got {subscribers_after!r}"

    # The dead budget name is not just unreadable, it is unusable: a mutation against
    # it fails the same way a fresh describe does.
    error = _client_error(
        lambda: budgets.create_notification(
            AccountId=account_id,
            BudgetName=name,
            Notification=notification,
            Subscribers=[{"SubscriptionType": "EMAIL", "Address": "sim2real-budgets-casc@example.com"}],
        )
    )
    assert error["Code"] == "NotFoundException", (
        f"expected NotFoundException creating on dead budget, got {error['Code']!r}"
    )
    assert error.get("Message") == gone_message, f"expected {gone_message!r}, got {error.get('Message')!r}"

    # The name is reusable, and a fresh budget under it starts with zero notifications —
    # proving no orphaned notification/subscriber row survived the cascade under the same name.
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
    reused_notifications = budgets.describe_notifications_for_budget(AccountId=account_id, BudgetName=name)[
        "Notifications"
    ]
    assert reused_notifications == [], (
        f"expected reused budget name to start with no notifications, got {reused_notifications!r}"
    )


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
