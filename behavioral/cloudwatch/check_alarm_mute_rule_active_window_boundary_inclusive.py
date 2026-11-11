"""alarm-mute-rule-active-window-boundary-inclusive."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags

CHECK = "alarm-mute-rule-active-window-boundary-inclusive"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cloudwatch"]


# timing:real-time — schedule: 60 s
@tags("axis:negative-delivery", "cap:c4", "concern:eventing", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """An alarm action delivers before any mute rule exists, is not delivered for an ALARM
    transition while a mute rule is ACTIVE, and delivers again (AlarmName, NewStateValue ALARM) for a
    fresh OK -> ALARM transition once the rule reports EXPIRED."""
    cw = ctx.client("cloudwatch")
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")

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

    alarm_name = ctx.unique_name("sim2real-mute-alarm-")
    namespace = ctx.unique_name("sim2real-mute-ns-")
    # A 1-day evaluation Period means the periodic evaluator will not re-run again
    # within this check's runtime, so our manually forced state transitions (below)
    # stick for the whole test instead of reverting to INSUFFICIENT_DATA within
    # seconds (as SetAlarmState's own docs warn a normally-scheduled alarm would).
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName="mute-rule-test-metric",
        Statistic="Maximum",
        Period=86400,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=True,
        AlarmActions=[topic["arn"]],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))
    # Start from a known state (OK) before the mute window begins. This first
    # transition (from the initial INSUFFICIENT_DATA) is not muted -- drain it so
    # it can't be mistaken for a leak during the "muted" assertion below.
    cw.set_alarm_state(AlarmName=alarm_name, StateValue="OK", StateReason="baseline-before-mute-window")
    _drain_messages(sqs, queue["url"], total_wait_s=10, poll_s=5)

    # Same-run positive control, before any mute rule exists: measure how long this
    # exact SNS->SQS wiring actually takes to deliver. Without this, a target whose
    # delivery is merely slow (not muted) could pass the "no delivery" assertion below
    # purely because our wait was shorter than its real latency -- a correct-but-slower
    # target must not be scored as having been muted.
    control_start = time.monotonic()
    cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason="pre-mute-window-positive-control")
    control_messages = _poll_until(
        lambda: _drain_messages(sqs, queue["url"], total_wait_s=5, poll_s=5),
        lambda msgs: len(msgs) >= 1,
        timeout_s=60,
        interval_s=5,
    )
    assert control_messages, "positive control: alarm action did not deliver before any mute rule existed"
    control_latency_s = time.monotonic() - control_start
    cw.set_alarm_state(AlarmName=alarm_name, StateValue="OK", StateReason="reset-after-positive-control")
    _drain_messages(sqs, queue["url"], total_wait_s=10, poll_s=5)

    # "at(...)" one-time mute windows are minute-precision (Syntax: at(yyyy-MM-ddThh:mm)).
    # The whole check has a hard wall-clock budget (300s), so we keep the window
    # as SHORT as the API allows: schedule for the very next minute boundary (with
    # a little safety margin for the PutAlarmMuteRule call to land) and use the
    # minimum PT1M duration.
    now = datetime.now(timezone.utc)
    next_minute = now.replace(second=0, microsecond=0) + timedelta(minutes=1)
    if (next_minute - now).total_seconds() < 20:
        next_minute += timedelta(minutes=1)
    window_start = next_minute
    window_end = window_start + timedelta(minutes=1)
    mute_rule_name = ctx.unique_name("sim2real-mute-rule-")
    cw.put_alarm_mute_rule(
        Name=mute_rule_name,
        Rule={"Schedule": {"Expression": f"at({window_start.strftime('%Y-%m-%dT%H:%M')})", "Duration": "PT1M"}},
        MuteTargets={"AlarmNames": [alarm_name]},
    )
    ctx.on_cleanup(lambda: cw.delete_alarm_mute_rule(AlarmMuteRuleName=mute_rule_name))

    # Wait for the mute rule to become ACTIVE.
    _poll_until(
        lambda: cw.get_alarm_mute_rule(AlarmMuteRuleName=mute_rule_name)["Status"],
        lambda status: status == "ACTIVE",
        timeout_s=(window_start - datetime.now(timezone.utc)).total_seconds() + 30,
        interval_s=3,
    )

    # Force the alarm into ALARM state while the mute rule is active: the
    # AlarmActions (SNS publish) should be muted, not delivered.
    cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason="mute-window-boundary-test-muted")
    muted_wait_s = max(10.0, 3 * control_latency_s)
    muted_messages = _drain_messages(sqs, queue["url"], total_wait_s=muted_wait_s, poll_s=5)
    assert muted_messages == [], (
        f"alarm action was NOT muted during the ACTIVE window (waited {muted_wait_s:.1f}s, "
        f">= 3x the {control_latency_s:.1f}s positive-control delivery latency): {muted_messages}"
    )

    # Wait for the mute rule to expire.
    _poll_until(
        lambda: cw.get_alarm_mute_rule(AlarmMuteRuleName=mute_rule_name)["Status"],
        lambda status: status == "EXPIRED",
        timeout_s=(window_end - datetime.now(timezone.utc)).total_seconds() + 30,
        interval_s=3,
    )

    # Now drive a FRESH transition (ALARM -> OK -> ALARM) after expiry -- not a
    # no-op restatement of the already-muted state -- and assert it delivers
    # normally, proving the suppression stopped exactly at the window's end
    # rather than lingering for some indefinite period after.
    cw.set_alarm_state(AlarmName=alarm_name, StateValue="OK", StateReason="reset-after-mute-window")
    cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason="mute-window-boundary-test-post-expiry")
    delivered = _poll_until(
        lambda: _drain_messages(sqs, queue["url"], total_wait_s=10, poll_s=5),
        lambda msgs: len(msgs) >= 1,
        timeout_s=90,
        interval_s=5,
    )
    assert len(delivered) >= 1, f"alarm action did not deliver after the mute window expired: {delivered}"
    envelope = delivered[0]
    assert envelope["AlarmName"] == alarm_name, f"expected AlarmName={alarm_name!r}, got {envelope.get('AlarmName')!r}"
    assert envelope["NewStateValue"] == "ALARM", f"expected NewStateValue='ALARM', got {envelope.get('NewStateValue')!r}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-mute-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _create_topic(ctx) -> dict[str, str]:
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=ctx.unique_name("sim2real-mute-topic-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return {"arn": arn}


def _drain_messages(sqs: Any, queue_url: str, *, total_wait_s: float, poll_s: float) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    deadline = time.monotonic() + total_wait_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=min(poll_s, max(int(deadline - time.monotonic()), 1)),
        )
        for msg in resp.get("Messages", []):
            try:
                envelope = json.loads(msg["Body"])
                payload = json.loads(envelope["Message"])
            except (KeyError, ValueError):
                payload = {}
            out.append(payload)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
