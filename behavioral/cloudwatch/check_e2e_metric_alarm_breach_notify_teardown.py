"""e2e-metric-alarm-breach-notify-teardown."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-metric-alarm-breach-notify-teardown"
GROUP = "e2e"
SERVICES = ["cloudwatch"]


# timing:real-time — metric: 40 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """PutMetricData breach -> alarm transitions to ALARM -> SNS action fires -> delete alarm removes it."""
    namespace = ctx.unique_name("Sim2RealBehav/AlarmE2E-")
    metric_name = "RequestErrors"
    alarm_name = ctx.unique_name("sim2real-behav-alarm-")

    queue = _create_queue(ctx)
    topic = _create_topic(ctx)
    _subscribe_queue_to_topic(ctx, topic, queue)

    cw = ctx.client("cloudwatch")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        AlarmDescription="sim2real behavioral breach test",
        Namespace=namespace,
        MetricName=metric_name,
        Statistic="Sum",
        Period=60,
        EvaluationPeriods=1,
        DatapointsToAlarm=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
        ActionsEnabled=True,
        AlarmActions=[topic["arn"]],
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_alarm_ignore(cw, alarm_name))

    # confirm the alarm exists before we drive it
    described = cw.describe_alarms(AlarmNames=[alarm_name])
    assert len(described["MetricAlarms"]) == 1, (
        f"expected exactly 1 alarm named {alarm_name!r} right after creation, "
        f"got {len(described['MetricAlarms'])}"
    )

    # write clearly-breaching datapoints repeatedly so the evaluator picks them up
    def _send_breach() -> None:
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {"MetricName": metric_name, "Value": 100.0, "Unit": "Count"},
            ],
        )

    _send_breach()

    def _probe_state() -> str:
        _send_breach()  # keep feeding data points while we wait for evaluation
        resp = cw.describe_alarms(AlarmNames=[alarm_name])
        alarms = resp["MetricAlarms"]
        return alarms[0]["StateValue"] if alarms else "MISSING"

    final_state = _poll_until(
        _probe_state, lambda s: s == "ALARM", timeout_s=600.0, interval_s=20.0
    )
    assert final_state == "ALARM", f"alarm never breached, last state={final_state}"

    # the ALARM transition must have fired the SNS action and landed on the subscribed queue
    messages = _wait_for_messages(ctx, queue["url"], expected_count=1, timeout_s=90.0)
    envelope = messages[0]["body"]
    assert isinstance(envelope, dict) and envelope.get("Type") == "Notification", (
        f"expected an SNS envelope with Type=Notification, got {envelope!r}"
    )
    inner = json.loads(envelope["Message"])
    assert inner["AlarmName"] == alarm_name, (
        f"notification named alarm {inner.get('AlarmName')!r}, expected {alarm_name!r}"
    )
    assert inner["NewStateValue"] == "ALARM", (
        f"notification NewStateValue={inner.get('NewStateValue')!r}, expected ALARM"
    )

    # now tear the alarm down and confirm it is gone
    cw.delete_alarms(AlarmNames=[alarm_name])
    after = cw.describe_alarms(AlarmNames=[alarm_name])
    assert after["MetricAlarms"] == [] and after["CompositeAlarms"] == [], (
        f"deleted alarm {alarm_name!r} still visible in DescribeAlarms: {after!r}"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(interval_s)
        value = probe()
    return value


def _delete_alarm_ignore(cw, name: str) -> None:
    try:
        cw.delete_alarms(AlarmNames=[name])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _create_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-alarmq-"),
        tags={"sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _create_topic(ctx) -> dict[str, str]:
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-alarmtopic-"),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return {"arn": arn}


def _subscribe_queue_to_topic(ctx, topic: dict[str, str], queue: dict[str, str]) -> None:
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")
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


def _wait_for_messages(ctx, queue_url: str, expected_count: int = 1, timeout_s: float = 60.0) -> list[dict[str, Any]]:
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
