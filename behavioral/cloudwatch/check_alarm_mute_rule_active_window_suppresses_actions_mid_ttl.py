"""alarm-mute-rule-active-window-suppresses-actions-mid-ttl."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "alarm-mute-rule-active-window-suppresses-actions-mid-ttl"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cloudwatch"]


# timing:real-time — schedule: 180 s
@tags("axis:negative-delivery", "cap:c4", "concern:eventing", "concern:metrics", "dp:api", "plane:data",
      "timing:real-time")
def run(ctx) -> None:
    """SetAlarmState to ALARM mid-way through an active mute rule window changes the state but
    delivers no SNS action to the subscribed queue; after the window expires the action arrives."""
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")
    cw = ctx.client("cloudwatch")

    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-cw-mute-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-cw-mute-topic-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

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
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    alarm_name = ctx.unique_name("sim2real-cw-mute-alarm-")
    ns = ctx.unique_name("sim2real-cw-mute-ns-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=ns,
        MetricName="MuteTestMetric",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
        ActionsEnabled=True,
        AlarmActions=[topic_arn],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    rule_name = ctx.unique_name("sim2real-cw-mute-rule-")
    minute_floor = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    expr = f"at({minute_floor.strftime('%Y-%m-%dT%H:%M')})"
    cw.put_alarm_mute_rule(
        Name=rule_name,
        Rule={"Schedule": {"Expression": expr, "Duration": "PT3M"}},
        MuteTargets={"AlarmNames": [alarm_name]},
    )
    ctx.on_cleanup(lambda: cw.delete_alarm_mute_rule(AlarmMuteRuleName=rule_name))

    _poll_until(lambda: cw.get_alarm_mute_rule(AlarmMuteRuleName=rule_name)["Status"] == "ACTIVE", timeout_s=60, interval_s=5)

    # Make sure we probe solidly mid-window, not right at the activation boundary.
    _poll_until(
        lambda: (datetime.now(timezone.utc) - minute_floor).total_seconds() >= 75,
        timeout_s=90,
        interval_s=5,
    )

    cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason="behavioral-check: mid mute window")
    alarm_state = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"]
    assert alarm_state == "ALARM", f"alarm should still transition state while muted, got {alarm_state}"
    muted_messages = _drain_messages(ctx, queue_url, timeout_s=20)
    assert muted_messages == [], f"alarm action fired while mute rule was active mid-window: {muted_messages}"

    _poll_until(lambda: cw.get_alarm_mute_rule(AlarmMuteRuleName=rule_name)["Status"] == "EXPIRED", timeout_s=200, interval_s=10)

    cw.set_alarm_state(AlarmName=alarm_name, StateValue="OK", StateReason="behavioral-check: reset before positive control")
    _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"] == "OK",
        timeout_s=30,
        interval_s=2,
    )
    cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason="behavioral-check: after mute window expired")
    unmuted_messages = _drain_messages(ctx, queue_url, timeout_s=60)
    assert len(unmuted_messages) >= 1, "alarm action did not fire after the mute rule expired (positive control failed)"


def _poll_until(predicate, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except Exception:
            pass
        time.sleep(interval_s)
    raise AssertionError("condition was not met within the timeout window")


def _drain_messages(ctx, queue_url, timeout_s=20.0):
    sqs = ctx.client("sqs")
    out = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        msgs = resp.get("Messages", [])
        for m in msgs:
            out.append(m)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
