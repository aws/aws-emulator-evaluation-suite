"""update-anomaly-subscription-rejects-conflicting-threshold."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-anomaly-subscription-rejects-conflicting-threshold"
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


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateAnomalySubscription rejects setting the deprecated Threshold and
    ThresholdExpression together, leaves the subscription's existing
    threshold untouched, and the subscription stays otherwise mutable.
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
            "ThresholdExpression": _THRESHOLD_EXPR,
        }
    )["SubscriptionArn"]
    ctx.on_cleanup(_teardown(
        lambda: ce.delete_anomaly_subscription(SubscriptionArn=sub_arn), "UnknownSubscriptionException"
    ))

    before = ce.get_anomaly_subscriptions(SubscriptionArnList=[sub_arn])["AnomalySubscriptions"][0]

    code, message = _error(lambda: ce.update_anomaly_subscription(
        SubscriptionArn=sub_arn,
        Threshold=50.0,
        ThresholdExpression=_THRESHOLD_EXPR,
    ))
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == "Threshold and ThresholdExpression cannot both be non-null", (
        f"unexpected message {message!r}"
    )

    unchanged = ce.get_anomaly_subscriptions(SubscriptionArnList=[sub_arn])["AnomalySubscriptions"][0]
    assert unchanged["ThresholdExpression"] == before["ThresholdExpression"], (
        f"the rejected update must leave ThresholdExpression unchanged: "
        f"before={before['ThresholdExpression']!r} after={unchanged['ThresholdExpression']!r}"
    )
    assert unchanged["Threshold"] == before["Threshold"], (
        f"the rejected update must leave Threshold unchanged: "
        f"before={before['Threshold']!r} after={unchanged['Threshold']!r}"
    )

    # Positive control: the subscription is still mutable after the rejection.
    renamed = ctx.unique_name("sim2real-behav-ce-sub-renamed-")
    ce.update_anomaly_subscription(SubscriptionArn=sub_arn, SubscriptionName=renamed)
    after_rename = ce.get_anomaly_subscriptions(SubscriptionArnList=[sub_arn])["AnomalySubscriptions"][0]
    assert after_rename["SubscriptionName"] == renamed, (
        f"expected the subscription to still accept a valid update after the rejection, "
        f"got name {after_rename['SubscriptionName']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
