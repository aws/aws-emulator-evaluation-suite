"""anomaly-subscription-update-changes-frequency-threshold-name."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "anomaly-subscription-update-changes-frequency-threshold-name"
GROUP = "anomaly-detection"
SERVICES = ["ce"]


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAnomalySubscription changes frequency, threshold expression and name in place,
    keeping the subscription's ARN and its monitor's single-subscription count unchanged.
    UpdateAnomalyMonitor renames a monitor in place, keeping its ARN too.
    """
    ce = ctx.client("ce")

    monitor_name = ctx.unique_name("sim2real-behav-ce-mon-")
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

    sub_name = ctx.unique_name("sim2real-behav-ce-sub-")
    sub_arn = ce.create_anomaly_subscription(
        AnomalySubscription={
            "SubscriptionName": sub_name,
            "MonitorArnList": [monitor_arn],
            "Subscribers": [{"Type": "EMAIL", "Address": "sim2real-ce-anomaly@example.com"}],
            "Frequency": "DAILY",
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

    sub_name_after = ctx.unique_name("sim2real-behav-ce-sub-renamed-")
    updated_arn = ce.update_anomaly_subscription(
        SubscriptionArn=sub_arn,
        SubscriptionName=sub_name_after,
        Frequency="WEEKLY",
        ThresholdExpression={
            "Dimensions": {
                "Key": "ANOMALY_TOTAL_IMPACT_ABSOLUTE",
                "Values": ["250"],
                "MatchOptions": ["GREATER_THAN_OR_EQUAL"],
            }
        },
    )["SubscriptionArn"]
    assert updated_arn == sub_arn, (
        f"UpdateAnomalySubscription must return the same SubscriptionArn it was called with: "
        f"expected {sub_arn!r}, got {updated_arn!r}"
    )

    by_arn = ce.get_anomaly_subscriptions(SubscriptionArnList=[sub_arn])["AnomalySubscriptions"]
    assert len(by_arn) == 1, (
        f"GetAnomalySubscriptions[{sub_arn!r}] must return exactly one subscription; got {by_arn!r}"
    )
    sub_after = by_arn[0]
    assert sub_after["SubscriptionName"] == sub_name_after, (
        f"expected the updated subscription name {sub_name_after!r}; got "
        f"{sub_after['SubscriptionName']!r}"
    )
    assert sub_after["Frequency"] == "WEEKLY", (
        f"expected the updated frequency WEEKLY; got {sub_after['Frequency']!r}"
    )
    dims_after = sub_after["ThresholdExpression"]["Dimensions"]
    assert dims_after["Key"] == "ANOMALY_TOTAL_IMPACT_ABSOLUTE", (
        f"expected the threshold dimension key to stay ANOMALY_TOTAL_IMPACT_ABSOLUTE; got "
        f"{dims_after['Key']!r}"
    )
    assert dims_after["Values"] == ["250"], (
        f"expected the updated threshold value ['250']; got {dims_after['Values']!r}"
    )
    assert dims_after["MatchOptions"] == ["GREATER_THAN_OR_EQUAL"], (
        f"expected the threshold match option to stay GREATER_THAN_OR_EQUAL; got "
        f"{dims_after['MatchOptions']!r}"
    )

    by_monitor = ce.get_anomaly_subscriptions(MonitorArn=monitor_arn)["AnomalySubscriptions"]
    assert [s["SubscriptionArn"] for s in by_monitor] == [sub_arn], (
        f"the monitor must still have exactly one subscription, the updated one, after the "
        f"update: got {[s['SubscriptionArn'] for s in by_monitor]!r}"
    )

    monitor_name_after = ctx.unique_name("sim2real-behav-ce-mon2-")
    updated_monitor_arn = ce.update_anomaly_monitor(
        MonitorArn=monitor_arn, MonitorName=monitor_name_after,
    )["MonitorArn"]
    assert updated_monitor_arn == monitor_arn, (
        f"UpdateAnomalyMonitor must return the same MonitorArn it was called with: "
        f"expected {monitor_arn!r}, got {updated_monitor_arn!r}"
    )

    monitors_after = ce.get_anomaly_monitors(MonitorArnList=[monitor_arn])["AnomalyMonitors"]
    assert len(monitors_after) == 1, (
        f"GetAnomalyMonitors[{monitor_arn!r}] must return exactly one monitor; got {monitors_after!r}"
    )
    assert monitors_after[0]["MonitorName"] == monitor_name_after, (
        f"expected the renamed monitor name {monitor_name_after!r}; got "
        f"{monitors_after[0]['MonitorName']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
