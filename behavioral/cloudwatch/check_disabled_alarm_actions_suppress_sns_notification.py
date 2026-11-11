"""disabled-alarm-actions-suppress-sns-notification."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "disabled-alarm-actions-suppress-sns-notification"
GROUP = "event-propagation"
SERVICES = ["cloudwatch"]


@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An alarm with ActionsEnabled=False reaches ALARM without delivering its SNS notification;
    after actions are enabled, a fresh OK -> ALARM transition delivers exactly one Notification
    (AlarmName, NewStateValue ALARM) to the subscribed SQS queue."""
    cw = ctx.client("cloudwatch")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-cw-topic-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-cw-queue-"),
        tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    policy = {
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
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})

    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)[
        "SubscriptionArn"
    ]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    alarm_name = ctx.unique_name("sim2real-behav-cw-actionalarm-")
    namespace = "Sim2Real/BehavioralCheck"
    metric_name = ctx.unique_name("ActionAlarmMetric-")

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName=metric_name,
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=100.0,
        ComparisonOperator="GreaterThanThreshold",
        AlarmActions=[topic_arn],
        ActionsEnabled=False,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    # Baseline INSUFFICIENT_DATA -> ALARM while actions are disabled: no delivery.
    cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason="suppressed transition")
    state = _poll_alarm_state(cw, alarm_name, "ALARM", timeout_s=30.0)
    assert state == "ALARM", f"expected alarm {alarm_name} to reach ALARM, last observed {state!r}"

    suppressed_messages = _drain_messages(sqs, queue_url, timeout_s=20.0)
    assert suppressed_messages == [], "notification delivered despite ActionsEnabled=False"

    # Positive control: enable actions, force a fresh OK->ALARM transition on the same
    # alarm, and confirm the notification is now delivered.
    cw.enable_alarm_actions(AlarmNames=[alarm_name])
    cw.set_alarm_state(AlarmName=alarm_name, StateValue="OK", StateReason="reset before re-trigger")
    _poll_alarm_state(cw, alarm_name, "OK", timeout_s=30.0)
    cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason="unsuppressed transition")
    _poll_alarm_state(cw, alarm_name, "ALARM", timeout_s=30.0)

    delivered = _wait_for_messages(sqs, queue_url, expected_count=1, timeout_s=60.0)
    assert len(delivered) == 1, f"expected exactly 1 notification once actions were re-enabled, got {len(delivered)}"
    envelope = json.loads(delivered[0]["Body"])
    assert envelope["Type"] == "Notification", f"expected an SNS Notification envelope, got Type={envelope.get('Type')!r}"
    payload = json.loads(envelope["Message"])
    assert payload["AlarmName"] == alarm_name, f"expected notification for {alarm_name}, got {payload.get('AlarmName')!r}"
    assert payload["NewStateValue"] == "ALARM", f"expected NewStateValue=ALARM, got {payload.get('NewStateValue')!r}"


def _poll_alarm_state(cw, alarm_name: str, expected: str, timeout_s: float, interval_s: float = 2.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        alarms = cw.describe_alarms(AlarmNames=[alarm_name]).get("MetricAlarms", [])
        if alarms:
            last = alarms[0]["StateValue"]
            if last == expected:
                return last
        time.sleep(interval_s)
    raise AssertionError(f"alarm {alarm_name} did not reach {expected!r} within {timeout_s}s, last observed {last!r}")


def _drain_messages(sqs, queue_url: str, timeout_s: float) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        msgs = resp.get("Messages", [])
        if not msgs:
            continue
        for msg in msgs:
            out.append(msg)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _wait_for_messages(sqs, queue_url: str, expected_count: int, timeout_s: float) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while len(out) < expected_count and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            out.append(msg)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    if len(out) < expected_count:
        raise AssertionError(f"expected {expected_count} messages, got {len(out)} in {timeout_s}s")
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
