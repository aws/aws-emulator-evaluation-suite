"""anomaly-subscription-threshold-shorthand-expands."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "anomaly-subscription-threshold-shorthand-expands"
GROUP = 'anomaly-detection'
SERVICES = ['ce']


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
    """Creating a subscription with only the deprecated Threshold field
    expands it into the equivalent ThresholdExpression on a later independent
    read, matching a subscription created with that expression directly.
    """
    ce = ctx.client("ce")
    sns = ctx.client("sns")

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

    topic_name = ctx.unique_name("sim2real-behav-ce-topic-")
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

    sub_name = ctx.unique_name("sim2real-behav-ce-sub-")
    sub_arn = ce.create_anomaly_subscription(
        AnomalySubscription={
            "SubscriptionName": sub_name,
            "MonitorArnList": [monitor_arn],
            "Subscribers": [{"Type": "SNS", "Address": topic_arn}],
            "Frequency": "IMMEDIATE",
            "Threshold": 75.0,
        }
    )["SubscriptionArn"]
    ctx.on_cleanup(_teardown(
        lambda: ce.delete_anomaly_subscription(SubscriptionArn=sub_arn), "UnknownSubscriptionException"
    ))

    read_back = ce.get_anomaly_subscriptions(SubscriptionArnList=[sub_arn])["AnomalySubscriptions"]
    assert len(read_back) == 1, f"expected the shorthand subscription to persist, got {read_back!r}"
    sub = read_back[0]

    assert sub["Threshold"] == 75.0, (
        f"expected the deprecated Threshold to read back as 75.0, got {sub['Threshold']!r}"
    )
    expr = sub["ThresholdExpression"]
    dims = expr["Dimensions"]
    assert dims["Key"] == "ANOMALY_TOTAL_IMPACT_ABSOLUTE", (
        f"expected the shorthand to expand to ANOMALY_TOTAL_IMPACT_ABSOLUTE, got {dims['Key']!r}"
    )
    assert dims["MatchOptions"] == ["GREATER_THAN_OR_EQUAL"], (
        f"expected the shorthand's match option to be GREATER_THAN_OR_EQUAL, got {dims['MatchOptions']!r}"
    )
    assert dims["Values"] == ["75.0"], (
        f"expected the shorthand's expanded value to be ['75.0'], got {dims['Values']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
