"""e2e-metric-breach-alarm-sns-notification-flow."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "e2e-metric-breach-alarm-sns-notification-flow"
GROUP = "e2e"
SERVICES = ["cloudwatch"]


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A breached metric alarm flips to ALARM, DescribeAlarmHistory records the transition,
    and the wired SNS action delivers a notification naming the alarm, state and metric."""
    namespace = ctx.unique_name("Sim2RealBehavSns")
    metric_name = "BreachMetric"
    alarm_name = ctx.unique_name("sim2real-cwsns-alarm-")

    topic = _create_topic(ctx)
    queue = _create_queue(ctx)
    _subscribe_queue_to_topic(ctx, topic, queue)

    cw = ctx.client("cloudwatch")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName=metric_name,
        Statistic="Maximum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
        AlarmActions=[topic["arn"]],
        Tags=_managed_tags(),
    )
    ctx.on_cleanup(lambda: _delete_alarm_quiet(ctx, alarm_name))

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": metric_name, "Value": 100.0, "Unit": "Count"}],
    )

    state = _poll_alarm_state(ctx, alarm_name, {"ALARM"}, timeout_s=600.0)
    assert state == "ALARM", f"expected ALARM, got {state}"

    history_items = cw.describe_alarm_history(
        AlarmName=alarm_name, HistoryItemType="StateUpdate"
    )["AlarmHistoryItems"]
    assert any(
        json.loads(item["HistoryData"]).get("newState", {}).get("stateValue") == "ALARM"
        for item in history_items
    ), "DescribeAlarmHistory does not record the transition into ALARM"

    notification = _wait_for_alarm_notification(ctx, queue["url"], alarm_name, timeout_s=120.0)
    assert notification["AlarmName"] == alarm_name, (
        f"expected notification for {alarm_name}, got {notification.get('AlarmName')!r}"
    )
    assert notification["NewStateValue"] == "ALARM", (
        f"expected NewStateValue=ALARM, got {notification.get('NewStateValue')!r}"
    )
    assert notification["Trigger"]["MetricName"] == metric_name, (
        f"expected Trigger.MetricName={metric_name!r}, got "
        f"{notification['Trigger'].get('MetricName')!r}"
    )
    assert notification["Trigger"]["Namespace"] == namespace, (
        f"expected Trigger.Namespace={namespace!r}, got {notification['Trigger'].get('Namespace')!r}"
    )

    cw.delete_alarms(AlarmNames=[alarm_name])
    remaining = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"]
    assert remaining == [], "alarm still present after DeleteAlarms"


def _managed_tags() -> list[dict[str, str]]:
    return [
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "sim2real:prefix", "Value": "sim2real-cwsns"},
    ]


def _create_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-cwsns-q-"),
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-cwsns"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _create_topic(ctx) -> dict[str, str]:
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-cwsns-topic-"), Tags=_managed_tags()
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return {"arn": arn}


def _subscribe_queue_to_topic(ctx, topic: dict[str, str], queue: dict[str, str]) -> None:
    sqs = ctx.client("sqs")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue["arn"],
                "Condition": {"ArnEquals": {"aws:SourceArn": topic["arn"]}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)})
    sns = ctx.client("sns")
    sub = sns.subscribe(TopicArn=topic["arn"], Protocol="sqs", Endpoint=queue["arn"])
    ctx.on_cleanup(lambda arn=sub["SubscriptionArn"]: ctx.client("sns").unsubscribe(SubscriptionArn=arn))


def _delete_alarm_quiet(ctx, alarm_name: str) -> None:
    cw = ctx.client("cloudwatch")
    cw.delete_alarms(AlarmNames=[alarm_name])


def _poll_alarm_state(ctx, alarm_name: str, target_states, timeout_s: float = 600.0, interval_s: float = 15.0):
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cw.describe_alarms(AlarmNames=[alarm_name])
        alarms = resp.get("MetricAlarms", [])
        if alarms:
            last = alarms[0]["StateValue"]
            if last in target_states:
                return last
        time.sleep(interval_s)
    return last


def _wait_for_alarm_notification(ctx, queue_url: str, alarm_name: str, timeout_s: float = 120.0) -> dict[str, Any]:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            envelope = json.loads(msg["Body"])
            notification = json.loads(envelope["Message"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if notification.get("AlarmName") == alarm_name:
                return notification
    raise AssertionError(f"no SNS alarm notification for {alarm_name} arrived within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
