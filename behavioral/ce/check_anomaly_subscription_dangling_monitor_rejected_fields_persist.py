"""anomaly-subscription-dangling-monitor-rejected-fields-persist."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "anomaly-subscription-dangling-monitor-rejected-fields-persist"
GROUP = "anomaly-subscription-validation"
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


def _error_code_and_message(fn) -> tuple[str, str]:
    """The (Error.Code, Error.Message) ``fn`` raises; raises on an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _find_by_name(ce, name: str) -> dict | None:
    kwargs: dict = {}
    while True:
        page = ce.get_anomaly_subscriptions(**kwargs)
        for sub in page["AnomalySubscriptions"]:
            if sub["SubscriptionName"] == name:
                return sub
        token = page.get("NextPageToken")
        if not token:
            return None
        kwargs["NextPageToken"] = token


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAnomalySubscription against a never-created monitor ARN raises
    UnknownMonitorException and creates nothing; the identical request against a real
    monitor succeeds and reads back its exact MonitorArnList, Frequency and ThresholdExpression.
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

    threshold_expression = {
        "Dimensions": {
            "Key": "ANOMALY_TOTAL_IMPACT_ABSOLUTE",
            "Values": ["200"],
            "MatchOptions": ["GREATER_THAN_OR_EQUAL"],
        }
    }
    subscribers = [{"Type": "EMAIL", "Address": "sim2real-behav-ce-anomaly@example.com"}]

    dangling_monitor_id = str(uuid.uuid4())
    dangling_monitor_arn = f"arn:aws:ce::{ctx.account}:anomalymonitor/{dangling_monitor_id}"
    bad_sub_name = ctx.unique_name("sim2real-behav-ce-bad-sub-")

    def _create_bad_subscription():
        return ce.create_anomaly_subscription(
            AnomalySubscription={
                "SubscriptionName": bad_sub_name,
                "MonitorArnList": [dangling_monitor_arn],
                "Frequency": "DAILY",
                "Subscribers": subscribers,
                "ThresholdExpression": threshold_expression,
            }
        )

    code, message = _error_code_and_message(_create_bad_subscription)
    assert code == "UnknownMonitorException", (
        f"a MonitorArnList naming a never-created monitor must raise UnknownMonitorException, "
        f"got {code!r}"
    )
    assert message == f"No monitor present with monitorId: {dangling_monitor_id}", (
        f"expected the exact UnknownMonitorException message AWS returns, got {message!r}"
    )

    assert _find_by_name(ce, bad_sub_name) is None, (
        f"the rejected subscription {bad_sub_name!r} must never have been created"
    )

    good_sub_name = ctx.unique_name("sim2real-behav-ce-good-sub-")
    good_sub_arn = ce.create_anomaly_subscription(
        AnomalySubscription={
            "SubscriptionName": good_sub_name,
            "MonitorArnList": [monitor_arn],
            "Frequency": "DAILY",
            "Subscribers": subscribers,
            "ThresholdExpression": threshold_expression,
        }
    )["SubscriptionArn"]
    ctx.on_cleanup(_teardown(
        lambda: ce.delete_anomaly_subscription(SubscriptionArn=good_sub_arn),
        "UnknownSubscriptionException",
    ))

    read_back = ce.get_anomaly_subscriptions(SubscriptionArnList=[good_sub_arn])[
        "AnomalySubscriptions"
    ]
    assert len(read_back) == 1, (
        f"GetAnomalySubscriptions(SubscriptionArnList=[{good_sub_arn!r}]) returned "
        f"{len(read_back)} subscriptions, expected exactly 1"
    )
    sub = read_back[0]

    assert sub["MonitorArnList"] == [monitor_arn], (
        f"expected MonitorArnList to read back as {[monitor_arn]!r}, got {sub['MonitorArnList']!r}"
    )
    assert sub["Frequency"] == "DAILY", (
        f"expected Frequency to read back as 'DAILY', got {sub['Frequency']!r}"
    )
    assert sub["ThresholdExpression"] == threshold_expression, (
        f"expected ThresholdExpression to read back exactly as submitted "
        f"{threshold_expression!r}, got {sub['ThresholdExpression']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
