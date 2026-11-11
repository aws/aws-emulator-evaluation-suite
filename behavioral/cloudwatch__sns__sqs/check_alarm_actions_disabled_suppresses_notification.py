"""alarm-actions-disabled-suppresses-notification."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "alarm-actions-disabled-suppresses-notification"

GROUP = "alerting"

SERVICES = ["cloudwatch", "sns", "sqs"]


@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """ActionsEnabled=false and DisableAlarmActions suppress the SNS alarm action while the alarm
    state still transitions and is recorded in history; re-enabling actions delivers again.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_DisableAlarmActions.html
    """
    topic, queue = _topic_to_queue(ctx)
    cw = ctx.client("cloudwatch")

    muted = _put_alarm(ctx, topic["arn"], actions_enabled=False)
    cw.set_alarm_state(
        AlarmName=muted, StateValue="ALARM", StateReason="probe: muted alarm to ALARM"
    )

    # (3) The STATE transition must still happen -- suppression is action-only.
    state = _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[muted])["MetricAlarms"][0]["StateValue"],
        lambda s: s == "ALARM",
        timeout_s=60,
        interval_s=2.0,
        description=f"muted alarm {muted} still transitions to ALARM",
    )
    assert state == "ALARM", (
        f"ActionsEnabled=False must not block the state machine; {muted} is {state!r}"
    )
    history = cw.describe_alarm_history(
        AlarmName=muted, HistoryItemType="StateUpdate", MaxRecords=10
    )["AlarmHistoryItems"]
    assert history, (
        f"ActionsEnabled=False must still record the StateUpdate in alarm history for {muted}"
    )

    # (4) A live control alarm on the SAME topic proves the delivery path is up. Its notification
    # arriving with nothing from the muted alarm ahead of it is the negative-delivery evidence.
    control = _put_alarm(ctx, topic["arn"], actions_enabled=True)
    cw.set_alarm_state(
        AlarmName=control, StateValue="ALARM", StateReason="probe: control alarm to ALARM"
    )
    matched, seen = _await_payload(
        ctx,
        queue["url"],
        lambda p: p.get("AlarmName") == control,
        timeout_s=180,
        description=f"control alarm {control} notification",
    )
    assert matched["NewStateValue"] == "ALARM", matched
    leaked = [p.get("AlarmName") for p in seen if p.get("AlarmName") == muted]
    assert not leaked, (
        f"ActionsEnabled=False must suppress delivery, but a notification for {muted} "
        f"was delivered (payloads seen: {[p.get('AlarmName') for p in seen]})"
    )

    # (5) Control case on the SAME alarm: re-enable actions, drive a fresh transition, delivered.
    cw.enable_alarm_actions(AlarmNames=[muted])
    cw.set_alarm_state(
        AlarmName=muted, StateValue="OK", StateReason="probe: reset to OK (no OKActions)"
    )
    cw.set_alarm_state(
        AlarmName=muted, StateValue="ALARM", StateReason="probe: re-enabled -> ALARM"
    )
    notify_started = time.monotonic()
    matched, _ = _await_payload(
        ctx,
        queue["url"],
        lambda p: p.get("AlarmName") == muted,
        timeout_s=180,
        description=f"re-enabled alarm {muted} notification",
    )
    # The drains below are sized from how long this live notification took to arrive.
    notify_latency_s = time.monotonic() - notify_started
    assert matched["NewStateValue"] == "ALARM", (
        f"re-enabled alarm notified with NewStateValue={matched.get('NewStateValue')!r}"
    )
    assert matched["OldStateValue"] == "OK", (
        f"expected OldStateValue=OK for the OK->ALARM transition, got "
        f"{matched.get('OldStateValue')!r}"
    )

    # (6) DisableAlarmActions must suppress just as ActionsEnabled=False did at creation time.
    # The alarm above just delivered, so the path is proven live; disabling is the only change.
    cw.disable_alarm_actions(AlarmNames=[muted])
    _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[muted])["MetricAlarms"],
        lambda a: a and a[0].get("ActionsEnabled") is False,
        timeout_s=60,
        interval_s=2.0,
        description=f"ActionsEnabled=False visible in DescribeAlarms for {muted}",
    )
    cw.set_alarm_state(
        AlarmName=muted, StateValue="OK", StateReason="probe: reset before disabled transition"
    )
    # discard notifications for the reset itself
    _drain(ctx, queue["url"], window_s=max(5.0, 2.0 * notify_latency_s))
    cw.set_alarm_state(
        AlarmName=muted, StateValue="ALARM", StateReason="probe: disabled -> ALARM"
    )
    state = cw.describe_alarms(AlarmNames=[muted])["MetricAlarms"][0]["StateValue"]
    assert state == "ALARM", (
        f"DisableAlarmActions must not block the state machine; {muted} is {state!r}"
    )
    leaked_after_disable = [
        p
        for p in _drain(ctx, queue["url"], window_s=max(10.0, 3.0 * notify_latency_s))
        if p.get("NewStateValue") == "ALARM"
    ]
    assert leaked_after_disable == [], (
        f"DisableAlarmActions did not suppress the action -- {len(leaked_after_disable)} ALARM "
        f"notification(s) were published: {leaked_after_disable}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _create_queue(ctx, fifo: bool = False, **attrs: str) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    base = _xname(ctx, "q")
    name = f"{base}.fifo" if fifo else base
    sqs = ctx.client("sqs")
    create_attrs = dict(attrs)
    if fifo:
        create_attrs["FifoQueue"] = "true"
    resp = sqs.create_queue(
        QueueName=name, Attributes=create_attrs, tags=_xsvc_resource_tags()
    )
    url = resp["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"name": name, "url": url, "arn": arn}


def _create_topic(ctx) -> dict[str, str]:
    """Create an SNS topic (registers delete_topic teardown). Returns {name,arn}."""
    name = _xname(ctx, "topic")
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=name, Tags=_xsvc_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return {"name": name, "arn": arn}


def _topic_to_queue(ctx) -> tuple[dict, dict]:
    """Create an SNS topic + an SQS queue subscribed to it (with the queue policy SNS needs)."""
    topic = _create_topic(ctx)
    queue = _create_queue(ctx)
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
    sqs.set_queue_attributes(
        QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)}
    )
    sns = ctx.client("sns")
    sub = sns.subscribe(TopicArn=topic["arn"], Protocol="sqs", Endpoint=queue["arn"])
    ctx.on_cleanup(
        lambda: ctx.client("sns").unsubscribe(SubscriptionArn=sub["SubscriptionArn"])
    )
    return topic, queue


def _put_alarm(
    ctx, topic_arn: str, *, actions_enabled: bool = True, ok_action: bool = False
) -> str:
    """Create a metric alarm whose AlarmActions publish to the topic; returns the alarm name.

    The metric is a private namespace/name that is never fed data -- state is driven with
    SetAlarmState, so the threshold/period values only need to be well-formed.
    """
    cw = ctx.client("cloudwatch")
    name = _xname(ctx, "alarm")
    kwargs: dict[str, Any] = dict(
        AlarmName=name,
        MetricName="probe-metric",
        Namespace="SimParity/CrossService",
        Statistic="Sum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanOrEqualToThreshold",
        ActionsEnabled=actions_enabled,
        AlarmActions=[topic_arn],
        Tags=_xsvc_tags_kv(),
    )
    if ok_action:
        kwargs["OKActions"] = [topic_arn]
    cw.put_metric_alarm(**kwargs)
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[name]))
    return name


def _alarm_payload(raw: str) -> dict[str, Any] | None:
    """Parse one SQS body into the CloudWatch alarm notification dict, or None if it is not one.

    SNS default (non-raw) delivery wraps the alarm JSON in an SNS envelope whose ["Message"] is
    itself a JSON string of the CloudWatch alarm notification.
    """
    try:
        envelope = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(envelope, dict) or envelope.get("Type") != "Notification":
        return None
    try:
        payload = json.loads(envelope["Message"])
    except (KeyError, json.JSONDecodeError, ValueError, TypeError):
        return None
    return payload if isinstance(payload, dict) else None


def _await_payload(
    ctx, queue_url: str, predicate, *, timeout_s=180.0, description="alarm notification"
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Poll SQS until an alarm payload satisfying predicate arrives.

    Returns (matched_payload, all_payloads_seen_in_order). The full list is the negative-delivery
    evidence: anything delivered ahead of the expected payload shows up in it.
    """
    sqs = ctx.client("sqs")
    seen: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            payload = _alarm_payload(msg.get("Body", ""))
            if payload is None:
                continue
            seen.append(payload)
            if predicate(payload):
                return payload, seen
    raise AssertionError(
        f"{description} not delivered within {timeout_s}s. "
        f"Payloads seen: {[p.get('AlarmName') for p in seen]}"
    )


def _drain(
    ctx, queue_url: str, *, window_s: float = 30.0, max_total: int = 10
) -> list[dict[str, Any]]:
    """Drain a queue over a bounded window and return every alarm payload seen. Never raises.

    This is the NEGATIVE observable, and it is only meaningful because a positive delivery on this
    same queue has already been observed earlier in the check -- that is what proves enough
    wall-clock and propagation elapsed for a leak to have surfaced. Used alone it would pass
    against an emulator that delivers nothing at all.
    """
    sqs = ctx.client("sqs")
    seen: list[dict[str, Any]] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline and len(seen) < max_total:
        wait = min(5, max(1, int(deadline - time.monotonic())))
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            payload = _alarm_payload(msg.get("Body", ""))
            if payload is not None:
                seen.append(payload)
    return seen


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
