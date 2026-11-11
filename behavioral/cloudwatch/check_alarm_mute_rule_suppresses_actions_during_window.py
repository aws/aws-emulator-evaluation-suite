"""alarm-mute-rule-suppresses-actions-during-window."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "alarm-mute-rule-suppresses-actions-during-window"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cloudwatch"]


# timing:real-time — schedule: 129 s
@tags("axis:negative-delivery", "cap:c4", "concern:data-plane", "concern:eventing", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Alarm actions are suppressed while a mute rule's window is ACTIVE and resume once it EXPIREs."""
    cw = ctx.client("cloudwatch")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    queue_url, queue_arn = _create_queue(ctx)
    topic_arn = _create_topic(ctx)

    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    alarm_name = ctx.unique_name("sim2real-amr-mutee-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        ComparisonOperator="GreaterThanThreshold",
        EvaluationPeriods=1,
        MetricName="sim2real-amr-mute-metric",
        Namespace="Sim2RealBehavioral",
        Period=60,
        Statistic="Average",
        Threshold=100.0,
        ActionsEnabled=True,
        AlarmActions=[topic_arn],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    # A one-time mute window that is already active: starting one minute before the minute
    # floor, PT4M leaves at least ~2 min of window after the ACTIVE poll, whatever the phase.
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    start = now - timedelta(minutes=1)
    rule_name = ctx.unique_name("sim2real-amr-window-")
    cw.put_alarm_mute_rule(
        Name=rule_name,
        Rule={"Schedule": {"Expression": f"at({start.strftime('%Y-%m-%dT%H:%M')})", "Duration": "PT4M", "Timezone": "UTC"}},
        MuteTargets={"AlarmNames": [alarm_name]},
    )
    ctx.on_cleanup(lambda: _safe_delete_rule(cw, rule_name))

    status = _poll_until(
        lambda: cw.get_alarm_mute_rule(AlarmMuteRuleName=rule_name)["Status"],
        lambda s: s == "ACTIVE",
        timeout_s=30.0,
        ctx=ctx,
    )
    assert status == "ACTIVE", f"mute rule never became ACTIVE (last status={status})"

    # Force a state transition while muted: action must NOT be delivered.
    cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason="sim2real-muted-transition")
    muted_messages = _drain_queue(sqs, queue_url, timeout_s=25.0)
    assert not muted_messages, f"expected no SNS delivery while muted, got {muted_messages}"

    # Wait for the mute window to expire.
    status = _poll_until(
        lambda: cw.get_alarm_mute_rule(AlarmMuteRuleName=rule_name)["Status"],
        lambda s: s == "EXPIRED",
        timeout_s=240.0,
        ctx=ctx,
    )
    assert status == "EXPIRED", f"mute rule never expired (last status={status})"

    # Reset to OK first: SetAlarmState only invokes actions when the state value actually
    # changes, so repeating ALARM->ALARM here would deliver nothing regardless of muting.
    cw.set_alarm_state(AlarmName=alarm_name, StateValue="OK", StateReason="sim2real-reset-before-positive-control")
    ok_status = _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"],
        lambda s: s == "OK",
        timeout_s=30.0,
        ctx=ctx,
    )
    assert ok_status == "OK", f"alarm never reset to OK before positive control (last status={ok_status})"

    # Force another state transition after expiry: action must now be delivered.
    cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason="sim2real-unmuted-transition")
    resumed_messages = _drain_queue(sqs, queue_url, timeout_s=45.0)
    assert resumed_messages, "expected SNS delivery after mute window expired, got none"
    envelope = json.loads(resumed_messages[0])
    assert envelope["Type"] == "Notification", f"unexpected SQS body shape: {envelope}"
    payload = json.loads(envelope["Message"])
    assert payload["AlarmName"] == alarm_name, payload
    assert payload["NewStateValue"] == "ALARM", payload


# ===== helpers =====
def _safe_delete_rule(cw, rule_name):
    try:
        cw.delete_alarm_mute_rule(AlarmMuteRuleName=rule_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFound", "ResourceNotFoundException"):
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0, ctx=None):
    left = ctx.time_left() if ctx is not None else None
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    result = None
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    return result


def _create_queue(ctx):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-amr-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_topic(ctx):
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=ctx.unique_name("sim2real-amr-topic-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


def _drain_queue(sqs, queue_url, timeout_s=25.0):
    out = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            out.append(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        if out:
            break
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
