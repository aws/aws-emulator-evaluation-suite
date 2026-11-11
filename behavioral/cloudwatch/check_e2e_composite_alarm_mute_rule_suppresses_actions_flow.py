"""e2e-composite-alarm-mute-rule-suppresses-actions-flow."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

from behavioral_harness import tags

CHECK = "e2e-composite-alarm-mute-rule-suppresses-actions-flow"
GROUP = "e2e"
SERVICES = ["cloudwatch"]


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A composite alarm targeted by an active mute rule enters ALARM without firing its SNS action,
    then fires it once the mute rule is deleted while the alarm is still in ALARM.
    Ending a mute re-triggers actions for an alarm that is still alarming."""
    namespace = ctx.unique_name("Sim2RealBehavMute")
    metric_name = "ChildMetric"
    child1_name = ctx.unique_name("sim2real-cwmute-child1-")
    child2_name = ctx.unique_name("sim2real-cwmute-child2-")
    composite_name = ctx.unique_name("sim2real-cwmute-composite-")
    mute_rule_name = ctx.unique_name("sim2real-cwmute-rule-")

    topic = _create_topic(ctx)
    queue = _create_queue(ctx)
    _subscribe_queue_to_topic(ctx, topic, queue)

    cw = ctx.client("cloudwatch")
    for child_name in (child1_name, child2_name):
        cw.put_metric_alarm(
            AlarmName=child_name,
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=[{"Name": "Child", "Value": child_name}],
            Statistic="Maximum",
            Period=60,
            EvaluationPeriods=1,
            Threshold=1,
            ComparisonOperator="GreaterThanThreshold",
            TreatMissingData="notBreaching",
            Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        )
        ctx.on_cleanup(lambda n=child_name: cw.delete_alarms(AlarmNames=[n]))

    alarm_rule = f'ALARM("{child1_name}") OR ALARM("{child2_name}")'
    cw.put_composite_alarm(
        AlarmName=composite_name,
        AlarmRule=alarm_rule,
        AlarmActions=[topic["arn"]],
        ActionsEnabled=True,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[composite_name]))

    at_time = (datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M")
    cw.put_alarm_mute_rule(
        Name=mute_rule_name,
        Rule={"Schedule": {"Expression": f"at({at_time})", "Duration": "PT30M", "Timezone": "UTC"}},
        MuteTargets={"AlarmNames": [composite_name]},
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    mute_rule_deleted = False
    ctx.on_cleanup(lambda: None if mute_rule_deleted else cw.delete_alarm_mute_rule(AlarmMuteRuleName=mute_rule_name))

    _poll_mute_rule_status(ctx, mute_rule_name, {"ACTIVE"}, timeout_s=120.0)

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {"MetricName": metric_name, "Dimensions": [{"Name": "Child", "Value": child1_name}], "Value": 100.0}
        ],
    )
    state = _poll_alarm_state(ctx, composite_name, {"ALARM"}, timeout_s=600.0)
    if state != "ALARM" and _budget_spent(ctx):
        raise TimeoutError("the composite alarm to reach ALARM: the run budget ended first; not graded")
    assert state == "ALARM", f"expected composite alarm ALARM, got {state}"

    muted_messages = _drain_messages(ctx, queue["url"], timeout_s=60.0)
    assert muted_messages == [], (
        f"alarm action fired while mute rule was ACTIVE: {muted_messages}"
    )

    cw.delete_alarm_mute_rule(AlarmMuteRuleName=mute_rule_name)
    mute_rule_deleted = True

    notification = _wait_for_alarm_notification(ctx, queue["url"], composite_name, timeout_s=120.0)
    assert notification["AlarmName"] == composite_name, (
        f"expected post-unmute notification for {composite_name!r}, got {notification.get('AlarmName')!r}"
    )
    assert notification["NewStateValue"] == "ALARM", (
        f"expected post-unmute notification NewStateValue 'ALARM', got {notification.get('NewStateValue')!r}"
    )


def _create_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-cwmute-q-"),
        tags={"sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _create_topic(ctx) -> dict[str, str]:
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-cwmute-topic-"),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_alarm_state(ctx, alarm_name: str, target_states, timeout_s: float = 600.0, interval_s: float = 2.0):
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        resp = cw.describe_alarms(AlarmNames=[alarm_name], AlarmTypes=["CompositeAlarm", "MetricAlarm"])
        alarms = resp.get("MetricAlarms", []) + resp.get("CompositeAlarms", [])
        if alarms:
            last = alarms[0]["StateValue"]
            if last in target_states:
                return last
        time.sleep(interval_s)
    return last


def _poll_mute_rule_status(ctx, mute_rule_name: str, target_statuses, timeout_s: float = 120.0, interval_s: float = 1.0):
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        resp = cw.get_alarm_mute_rule(AlarmMuteRuleName=mute_rule_name)
        last = resp["Status"]
        if last in target_statuses:
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"mute rule {mute_rule_name} to reach {target_statuses}: the run budget "
                           f"ended first; not graded")
    raise AssertionError(f"mute rule {mute_rule_name} never reached {target_statuses}, last status {last}")


def _drain_messages(ctx, queue_url: str, timeout_s: float) -> list[dict[str, Any]]:
    sqs = ctx.client("sqs")
    out: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            out.append(json.loads(msg["Body"]))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _wait_for_alarm_notification(ctx, queue_url: str, alarm_name: str, timeout_s: float = 120.0) -> dict[str, Any]:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
        for msg in resp.get("Messages", []):
            envelope = json.loads(msg["Body"])
            notification = json.loads(envelope["Message"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if notification.get("AlarmName") == alarm_name:
                return notification
    if _budget_spent(ctx):
        raise TimeoutError(f"the post-unmute SNS notification for {alarm_name}: the run budget ended "
                           f"first; not graded")
    raise AssertionError(f"no post-unmute SNS notification for {alarm_name} arrived within the wait bound")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
