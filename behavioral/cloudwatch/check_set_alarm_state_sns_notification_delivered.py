"""set-alarm-state-sns-notification-delivered."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "set-alarm-state-sns-notification-delivered"
GROUP = "telemetry"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """An alarm wired with an SNS AlarmAction actually delivers a real
    notification (through a subscribed SQS queue) when SetAlarmState forces it
    into ALARM, and the notification payload correctly describes the transition."""
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")
    cw = ctx.client("cloudwatch")

    queue = _create_queue(ctx)
    topic = _create_topic(ctx)

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
    sub = sns.subscribe(TopicArn=topic["arn"], Protocol="sqs", Endpoint=queue["arn"])
    ctx.on_cleanup(lambda arn=sub["SubscriptionArn"]: sns.unsubscribe(SubscriptionArn=arn))

    alarm_name = ctx.unique_name("sim2real-behav-alarm-")
    namespace = ctx.unique_name("sim2real-behav-ns-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName="ErrorRate",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=True,
        AlarmActions=[topic["arn"]],
        TreatMissingData="missing",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    cw.set_alarm_state(
        AlarmName=alarm_name, StateValue="ALARM", StateReason="behavioral-test-forced-alarm"
    )

    messages = _wait_for_messages(ctx, queue["url"], expected_count=1, timeout_s=90)
    assert len(messages) == 1, f"expected exactly 1 SQS message, got {len(messages)}: {messages!r}"
    envelope = messages[0]["body"]
    assert isinstance(envelope, dict) and envelope["Type"] == "Notification", (
        f"expected an SNS notification envelope, got {envelope!r}"
    )
    payload = json.loads(envelope["Message"])
    assert payload["AlarmName"] == alarm_name, (
        f"notification AlarmName={payload['AlarmName']!r}, expected {alarm_name!r}"
    )
    assert payload["NewStateValue"] == "ALARM", (
        f"notification NewStateValue={payload['NewStateValue']!r}, expected 'ALARM'"
    )


def _create_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-q-"),
        tags={"sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _create_topic(ctx) -> dict[str, str]:
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-topic-"),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return {"arn": arn}


def _wait_for_messages(ctx, queue_url, expected_count=1, timeout_s=60.0):
    sqs = ctx.client("sqs")
    out: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while len(out) < expected_count and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            out.append({"body": body, "message_id": msg["MessageId"]})
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    if len(out) < expected_count:
        raise AssertionError(f"expected {expected_count} messages, got {len(out)} in {timeout_s}s")
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
