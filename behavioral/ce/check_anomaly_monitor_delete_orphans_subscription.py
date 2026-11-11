"""anomaly-monitor-delete-orphans-subscription."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "anomaly-monitor-delete-orphans-subscription"
GROUP = 'anomaly-detection'
SERVICES = ['ce']

_THRESHOLD_EXPR = {
    "Dimensions": {
        "Key": "ANOMALY_TOTAL_IMPACT_ABSOLUTE",
        "Values": ["100"],
        "MatchOptions": ["GREATER_THAN_OR_EQUAL"],
    }
}


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteAnomalyMonitor succeeds on a monitor an active subscription still
    references. The subscription survives with that monitor silently dropped
    from MonitorArnList, rather than being cascade-deleted or blocking the delete.
    """
    ce = ctx.client("ce")
    sns = ctx.client("sns")

    monitor_name = ctx.unique_name("sim2real-behav-ce-mon-")
    topic_name = ctx.unique_name("sim2real-behav-ce-topic-")
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

    topic_arn = sns.create_topic(Name=topic_name)["TopicArn"]
    ctx.on_cleanup(_teardown(lambda: sns.delete_topic(TopicArn=topic_arn), "NotFound"))
    sns.set_topic_attributes(
        TopicArn=topic_arn,
        AttributeName="Policy",
        AttributeValue=(
            '{"Version":"2012-10-17","Statement":[{"Sid":"sim2real-behav-ce-costalerts",'
            '"Effect":"Allow","Principal":{"Service":"costalerts.amazonaws.com"},'
            f'"Action":"SNS:Publish","Resource":"{topic_arn}"}}]}}'
        ),
    )

    sub_arn = ce.create_anomaly_subscription(
        AnomalySubscription={
            "SubscriptionName": sub_name,
            "MonitorArnList": [monitor_arn],
            "Subscribers": [{"Type": "SNS", "Address": topic_arn}],
            "Frequency": "IMMEDIATE",
            "ThresholdExpression": _THRESHOLD_EXPR,
        }
    )["SubscriptionArn"]
    ctx.on_cleanup(_teardown(
        lambda: ce.delete_anomaly_subscription(SubscriptionArn=sub_arn), "UnknownSubscriptionException"
    ))

    before = ce.get_anomaly_subscriptions(SubscriptionArnList=[sub_arn])["AnomalySubscriptions"][0]
    assert before["MonitorArnList"] == [monitor_arn], (
        f"expected the fresh subscription to list {monitor_arn!r}, got {before['MonitorArnList']!r}"
    )

    ce.delete_anomaly_monitor(MonitorArn=monitor_arn)

    after = ce.get_anomaly_subscriptions(SubscriptionArnList=[sub_arn])["AnomalySubscriptions"]
    assert len(after) == 1, (
        f"deleting the referenced monitor must not cascade-delete the subscription, "
        f"but GetAnomalySubscriptions returned {len(after)} record(s)"
    )
    after_sub = after[0]
    assert after_sub["MonitorArnList"] == [], (
        f"expected the deleted monitor to be dropped from MonitorArnList, "
        f"got {after_sub['MonitorArnList']!r}"
    )
    assert after_sub["SubscriptionName"] == sub_name, (
        f"expected the surviving subscription's name to stay {sub_name!r}, "
        f"got {after_sub['SubscriptionName']!r}"
    )
    assert after_sub["Subscribers"] == before["Subscribers"], (
        f"expected Subscribers to be unaffected by the monitor's deletion, "
        f"before={before['Subscribers']!r} after={after_sub['Subscribers']!r}"
    )

    gone = ce.get_anomaly_monitors(MonitorArnList=[monitor_arn])["AnomalyMonitors"]
    assert gone == [], f"expected the deleted monitor to be gone, got {gone!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
