"""anomaly-subscription-accepts-unreachable-sns."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "anomaly-subscription-accepts-unreachable-sns"
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAnomalySubscription does not validate that an SNS subscriber
    topic exists or grants costalerts publish permission: a subscriber on a
    topic that was never created persists the same way a real, granted one does.
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

    # The positive control: a real topic, created and granted publish rights.
    real_topic_name = ctx.unique_name("sim2real-behav-ce-realtopic-")
    real_topic_arn = sns.create_topic(Name=real_topic_name)["TopicArn"]
    ctx.on_cleanup(_teardown(lambda: sns.delete_topic(TopicArn=real_topic_arn), "NotFound"))
    sns.set_topic_attributes(
        TopicArn=real_topic_arn,
        AttributeName="Policy",
        AttributeValue=(
            '{"Version":"2012-10-17","Statement":[{"Sid":"sim2real-behav-ce-costalerts",'
            '"Effect":"Allow","Principal":{"Service":"costalerts.amazonaws.com"},'
            f'"Action":"SNS:Publish","Resource":"{real_topic_arn}"}}]}}'
        ),
    )
    real_sub_name = ctx.unique_name("sim2real-behav-ce-realsub-")
    real_sub_arn = ce.create_anomaly_subscription(
        AnomalySubscription={
            "SubscriptionName": real_sub_name,
            "MonitorArnList": [monitor_arn],
            "Subscribers": [{"Type": "SNS", "Address": real_topic_arn}],
            "Frequency": "IMMEDIATE",
            "ThresholdExpression": _THRESHOLD_EXPR,
        }
    )["SubscriptionArn"]
    ctx.on_cleanup(_teardown(
        lambda: ce.delete_anomaly_subscription(SubscriptionArn=real_sub_arn),
        "UnknownSubscriptionException",
    ))

    # The subject: a subscriber on a topic that was never created at all, in
    # this same account and region, so the ARN cannot resolve to anything.
    fake_topic_arn = f"arn:aws:sns:{ctx.region}:{ctx.account}:{ctx.unique_name('sim2real-behav-ce-notopic-')}"
    fake_sub_name = ctx.unique_name("sim2real-behav-ce-fakesub-")
    fake_sub_arn = ce.create_anomaly_subscription(
        AnomalySubscription={
            "SubscriptionName": fake_sub_name,
            "MonitorArnList": [monitor_arn],
            "Subscribers": [{"Type": "SNS", "Address": fake_topic_arn}],
            "Frequency": "IMMEDIATE",
            "ThresholdExpression": _THRESHOLD_EXPR,
        }
    )["SubscriptionArn"]
    ctx.on_cleanup(_teardown(
        lambda: ce.delete_anomaly_subscription(SubscriptionArn=fake_sub_arn),
        "UnknownSubscriptionException",
    ))

    real = ce.get_anomaly_subscriptions(SubscriptionArnList=[real_sub_arn])["AnomalySubscriptions"]
    assert len(real) == 1, f"expected the real-topic subscription to persist, got {real!r}"
    real_subscriber = real[0]["Subscribers"][0]
    assert real_subscriber["Address"] == real_topic_arn, (
        f"expected real subscriber address {real_topic_arn!r}, got {real_subscriber['Address']!r}"
    )
    assert real_subscriber["Status"] == "CONFIRMED", (
        f"expected the policy-granted topic to read back CONFIRMED, got {real_subscriber['Status']!r}"
    )

    fake = ce.get_anomaly_subscriptions(SubscriptionArnList=[fake_sub_arn])["AnomalySubscriptions"]
    assert len(fake) == 1, f"expected the fake-topic subscription to persist too, got {fake!r}"
    fake_subscriber = fake[0]["Subscribers"][0]
    assert fake_subscriber["Address"] == fake_topic_arn, (
        f"expected fake subscriber address {fake_topic_arn!r}, got {fake_subscriber['Address']!r}"
    )
    assert fake_subscriber["Status"] == real_subscriber["Status"], (
        f"a subscriber on a topic that never existed read back {fake_subscriber['Status']!r}, "
        f"not the same {real_subscriber['Status']!r} a real, policy-granted topic gets — "
        "CreateAnomalySubscription does not distinguish them at creation time"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
