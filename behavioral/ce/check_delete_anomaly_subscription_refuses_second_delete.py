"""delete-anomaly-subscription-refuses-second-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-anomaly-subscription-refuses-second-delete"
GROUP = "anomaly-subscription-validation"
SERVICES = ["ce"]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAnomalySubscription for a subscription that exists answers HTTP 200 with an empty
    body, GetAnomalySubscriptions filtered by that ARN then no longer returns it, and a second
    DeleteAnomalySubscription for the same ARN is refused with UnknownSubscriptionException."""
    ce = ctx.client("ce")

    monitor_name = ctx.unique_name("sim2real-behav-ce-mon-")
    sub_name = ctx.unique_name("sim2real-behav-ce-sub-")

    monitor_arn = ce.create_anomaly_monitor(
        AnomalyMonitor={
            "MonitorName": monitor_name,
            "MonitorType": "DIMENSIONAL",
            "MonitorDimension": "SERVICE",
        }
    )["MonitorArn"]
    ctx.on_cleanup(_teardown(
        lambda: ce.delete_anomaly_monitor(MonitorArn=monitor_arn), "UnknownMonitorException"
    ))

    sub_arn = ce.create_anomaly_subscription(
        AnomalySubscription={
            "SubscriptionName": sub_name,
            "MonitorArnList": [monitor_arn],
            "Frequency": "DAILY",
            "Subscribers": [{"Type": "EMAIL", "Address": "sim2real-ce-anomaly@example.com"}],
            "ThresholdExpression": {
                "Dimensions": {
                    "Key": "ANOMALY_TOTAL_IMPACT_ABSOLUTE",
                    "Values": ["100"],
                    "MatchOptions": ["GREATER_THAN_OR_EQUAL"],
                }
            },
        }
    )["SubscriptionArn"]
    ctx.on_cleanup(_teardown(
        lambda: ce.delete_anomaly_subscription(SubscriptionArn=sub_arn), "UnknownSubscriptionException"
    ))

    before = ce.get_anomaly_subscriptions(SubscriptionArnList=[sub_arn])["AnomalySubscriptions"]
    assert len(before) == 1 and before[0]["SubscriptionArn"] == sub_arn, (
        f"expected the fresh subscription {sub_arn!r} to be listed, got {before!r}"
    )

    first_delete = ce.delete_anomaly_subscription(SubscriptionArn=sub_arn)
    assert first_delete["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected DeleteAnomalySubscription to answer HTTP 200, "
        f"got {first_delete['ResponseMetadata']['HTTPStatusCode']!r}"
    )
    body_keys = set(first_delete) - {"ResponseMetadata"}
    assert body_keys == set(), (
        f"expected an empty DeleteAnomalySubscription response body, got keys {body_keys!r}"
    )

    after = ce.get_anomaly_subscriptions(SubscriptionArnList=[sub_arn])["AnomalySubscriptions"]
    assert after == [], (
        f"expected GetAnomalySubscriptions filtered by the deleted ARN to return nothing, "
        f"got {after!r}"
    )

    subscription_id = sub_arn.rsplit("/", 1)[-1]
    _UNKNOWN_SUBSCRIPTION = (
        "UnknownSubscriptionException",
        f"No anomaly subscription present with resourceId: {subscription_id}",
    )
    expect_error(
        lambda: ce.delete_anomaly_subscription(SubscriptionArn=sub_arn),
        *_UNKNOWN_SUBSCRIPTION,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
