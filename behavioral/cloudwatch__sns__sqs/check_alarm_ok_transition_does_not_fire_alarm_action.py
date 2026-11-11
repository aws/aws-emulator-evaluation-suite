"""alarm-ok-transition-does-not-fire-alarm-action."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "alarm-ok-transition-does-not-fire-alarm-action"

GROUP = "alerting"

SERVICES = ["cloudwatch", "sns", "sqs"]


@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """An alarm with AlarmActions but no OKActions notifies on entering ALARM, and on returning to
    OK it records the transition but delivers nothing, while a sibling alarm with OKActions on the
    same topic notifies on its OK transition."""
    topic, queue = _topic_to_queue(ctx)
    cw = ctx.client("cloudwatch")

    # (1)+(2) Alarm with AlarmActions only. The ALARM transition must deliver.
    alarm_only = _put_alarm(ctx, topic["arn"], ok_action=False)
    cw.set_alarm_state(
        AlarmName=alarm_only, StateValue="ALARM", StateReason="probe: -> ALARM"
    )
    matched, _ = _await_payload(
        ctx,
        queue["url"],
        lambda p: p.get("AlarmName") == alarm_only,
        timeout_s=180,
        description=f"AlarmActions notification for {alarm_only}",
    )
    assert matched["NewStateValue"] == "ALARM", (
        f"expected NewStateValue=ALARM on the alarm notification, got "
        f"{matched.get('NewStateValue')!r}: {matched!r}"
    )

    # (3) The OK transition must change state but fire nothing.
    cw.set_alarm_state(
        AlarmName=alarm_only, StateValue="OK", StateReason="probe: -> OK (no OKActions)"
    )
    state = _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[alarm_only])["MetricAlarms"][0][
            "StateValue"
        ],
        lambda s: s == "OK",
        timeout_s=60,
        interval_s=2.0,
        description=f"{alarm_only} transitions to OK",
    )
    assert state == "OK", (
        f"the OK transition must still run the state machine; {alarm_only} is {state!r}"
    )
    updates = cw.describe_alarm_history(
        AlarmName=alarm_only, HistoryItemType="StateUpdate", MaxRecords=20
    )["AlarmHistoryItems"]
    assert len(updates) >= 2, (
        f"expected the ALARM and OK StateUpdates in history for {alarm_only}, got "
        f"{len(updates)} item(s)"
    )

    # (4) Control: a sibling WITH OKActions notifies on OK. Its arrival bounds the window in
    # which a leaked OK notification for `alarm_only` would have had to show up.
    both = _put_alarm(ctx, topic["arn"], ok_action=True)
    cw.set_alarm_state(AlarmName=both, StateValue="ALARM", StateReason="probe: -> ALARM")
    cw.set_alarm_state(AlarmName=both, StateValue="OK", StateReason="probe: -> OK")
    control, seen = _await_payload(
        ctx,
        queue["url"],
        lambda p: p.get("AlarmName") == both and p.get("NewStateValue") == "OK",
        timeout_s=180,
        description=f"OKActions notification for {both}",
    )
    assert control["OldStateValue"] == "ALARM", (
        f"expected OldStateValue=ALARM on the recovery notification, got "
        f"{control.get('OldStateValue')!r}"
    )
    leaked = [
        p
        for p in seen
        if p.get("AlarmName") == alarm_only and p.get("NewStateValue") == "OK"
    ]
    assert not leaked, (
        f"an alarm with no OKActions must not notify on its OK transition, but "
        f"{len(leaked)} notification(s) for {alarm_only} with NewStateValue=OK were delivered"
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
    """Parse one SQS body into the CloudWatch alarm notification dict, or None if it is not one."""
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
        f"Payloads seen: {[(p.get('AlarmName'), p.get('NewStateValue')) for p in seen]}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
