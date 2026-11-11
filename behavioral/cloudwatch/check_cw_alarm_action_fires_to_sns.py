"""cw-alarm-action-fires-to-sns."""
from __future__ import annotations

import json

from behavioral_harness import tags

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

CHECK = "cw-alarm-action-fires-to-sns"
GROUP = 'data-plane'
SERVICES = ['cloudwatch']

@tags("axis:happy-path", "cap:c1", "concern:eventing", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """An alarm driven to ALARM by SetAlarmState fires its SNS action: a notification naming the
    alarm with NewStateValue ALARM reaches the subscribed SQS queue."""
    cw = ctx.client("cloudwatch")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-topic-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    # Allow SNS to deliver to the queue.
    sqs.set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "sns.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": queue_arn,
                            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
                        }
                    ],
                }
            )
        },
    )
    sns.subscribe(
        TopicArn=topic_arn,
        Protocol="sqs",
        Endpoint=queue_arn,
        ReturnSubscriptionArn=True,
    )

    alarm_name = ctx.unique_name("sim2real-behav-alarm-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=ctx.unique_name("sim2real-behav-ns-"),
        MetricName="ActionMetric",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=True,
        AlarmActions=[topic_arn],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    # SetAlarmState with actions enabled fires the alarm action immediately.
    cw.set_alarm_state(
        AlarmName=alarm_name,
        StateValue="ALARM",
        StateReason="sim2real forced breach for action delivery",
    )

    def receive():
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        notifications = []
        for m in resp.get("Messages", []):
            try:
                envelope = json.loads(m.get("Body", ""))
            except (json.JSONDecodeError, ValueError):
                continue
            if not isinstance(envelope, dict) or envelope.get("Type") != "Notification":
                continue
            try:
                inner = json.loads(envelope.get("Message", ""))
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(inner, dict) and inner.get("AlarmName") == alarm_name:
                notifications.append(inner)
        return notifications

    notifications = _poll_until(
        receive,
        lambda ns: len(ns) > 0,
        timeout_s=120,
        interval_s=5,
        description="alarm SNS notification arriving in the SQS queue",
    )
    assert notifications, f"no SQS notification referenced alarm {alarm_name}"
    notification = notifications[0]
    assert notification["AlarmName"] == alarm_name, notification
    assert notification["NewStateValue"] == "ALARM", (
        f"expected NewStateValue=ALARM, got {notification.get('NewStateValue')!r}: {notification}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
