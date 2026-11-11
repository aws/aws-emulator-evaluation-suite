"""composite-alarm-unsatisfied-rule-no-action."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "composite-alarm-unsatisfied-rule-no-action"

GROUP = "alerting"

SERVICES = ["cloudwatch", "sns", "sqs"]


@tags("axis:negative-delivery", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A composite alarm whose AND rule is unsatisfied (one child in ALARM) stays OK and delivers
    nothing; driving the second child satisfies the rule, and that transition, dated no earlier
    than the second child's, is the first notification.
    """
    topic, queue = _topic_to_queue(ctx)
    cw = ctx.client("cloudwatch")

    # (1) Children carry no AlarmActions at all.
    child_a = _put_actionless_alarm(ctx)
    child_b = _put_actionless_alarm(ctx)
    cw.set_alarm_state(AlarmName=child_a, StateValue="OK", StateReason="probe: baseline")
    cw.set_alarm_state(AlarmName=child_b, StateValue="OK", StateReason="probe: baseline")

    # (2) Registered last => torn down FIRST (LIFO), because CloudWatch refuses to delete a child
    # alarm still referenced by a composite.
    composite = _xname(ctx, "composite")
    cw.put_composite_alarm(
        AlarmName=composite,
        AlarmRule=f'ALARM("{child_a}") AND ALARM("{child_b}")',
        ActionsEnabled=True,
        AlarmActions=[topic["arn"]],
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(
        lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[composite])
    )
    baseline = _poll_until(
        ctx,
        lambda: _composite_state(cw, composite),
        lambda s: s == "OK",
        timeout_s=_budget_s(ctx, 120),
        interval_s=2.0,
        description=f"composite {composite} server-evaluates to OK from two OK children",
    )
    assert baseline == "OK", f"composite baseline was {baseline!r}, expected OK"

    # (3) One child only -- the AND rule is unsatisfied.
    cw.set_alarm_state(
        AlarmName=child_a, StateValue="ALARM", StateReason="probe: single child breach"
    )
    child_state = _poll_until(
        ctx,
        lambda: cw.describe_alarms(AlarmNames=[child_a])["MetricAlarms"][0]["StateValue"],
        lambda s: s == "ALARM",
        timeout_s=_budget_s(ctx, 60),
        interval_s=2.0,
        description=f"child {child_a} reaches ALARM",
    )
    assert child_state == "ALARM", child_state
    # The snapshot reads the CHILDREN as well as the composite: "composite is OK" is evidence
    # about AND only while the asymmetric child states it is asked to evaluate actually hold.
    observed = (
        _composite_state(cw, composite),
        _child_state(cw, child_a),
        _child_state(cw, child_b),
    )
    assert observed == ("OK", "ALARM", "OK"), (
        f"composite {composite} must be OK while child {child_a} is ALARM and child {child_b} is "
        f"OK -- exactly one of two AND-ed children breaching -- observed {observed!r}"
    )

    # (4) Control: satisfy the rule. Its notification bounds the window in which an unsatisfied
    # -rule notification would have had to appear.
    assert _child_state(cw, child_a) == "ALARM", (
        f"child {child_a} must still be in ALARM when the second child is driven, or the AND rule "
        f"is never simultaneously satisfied and the control arm cannot fire"
    )
    cw.set_alarm_state(
        AlarmName=child_b, StateValue="ALARM", StateReason="probe: second child breach"
    )
    satisfied = _poll_until(
        ctx,
        lambda: _composite_state(cw, composite),
        lambda s: s == "ALARM",
        timeout_s=_budget_s(ctx, 120),
        interval_s=2.0,
        description=f"composite {composite} flips to ALARM once BOTH children are in ALARM",
    )
    assert satisfied == "ALARM", satisfied
    # The positive control is ordered after the forbidden event: a composite that went to ALARM
    # on child A alone would carry a transition older than child B's.
    child_b_at = _alarm(cw, child_b, "MetricAlarm")["StateUpdatedTimestamp"]
    composite_at = _alarm(cw, composite, "CompositeAlarm")["StateUpdatedTimestamp"]
    assert composite_at >= child_b_at, (
        f"composite {composite} entered ALARM at {composite_at!r}, before child {child_b} did at "
        f"{child_b_at!r}: the AND rule fired on one child"
    )

    payload, seen = _await_payload(
        ctx,
        queue["url"],
        lambda p: p.get("AlarmName") == composite,
        timeout_s=_budget_s(ctx, 180),
        description=f"notification for the satisfied composite {composite}",
    )
    assert payload["NewStateValue"] == "ALARM", payload
    assert payload["OldStateValue"] == "OK", (
        f"expected the composite's OK->ALARM transition, got OldStateValue="
        f"{payload.get('OldStateValue')!r}"
    )
    early = [p for p in seen if p is not payload]
    assert not early, (
        f"nothing may be delivered while the composite's AND rule is unsatisfied, but "
        f"{len(early)} notification(s) arrived first: "
        f"{[(p.get('AlarmName'), p.get('NewStateValue')) for p in early]}"
    )


def _composite_state(cw, name: str) -> str | None:
    described = cw.describe_alarms(AlarmNames=[name], AlarmTypes=["CompositeAlarm"]).get(
        "CompositeAlarms", []
    )
    return described[0]["StateValue"] if described else None


def _put_actionless_alarm(ctx) -> str:
    """A metric alarm with NO actions, driven by SetAlarmState; a pure composite input.

    No data is published, so TreatMissingData="ignore" keeps a SetAlarmState override from being
    re-evaluated away (missing, notBreaching and breaching each replace it within minutes).
    """
    cw = ctx.client("cloudwatch")
    name = _xname(ctx, "child")
    cw.put_metric_alarm(
        AlarmName=name,
        MetricName="probe-metric",
        Namespace="SimParity/CrossService",
        Statistic="Sum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanOrEqualToThreshold",
        TreatMissingData="ignore",
        ActionsEnabled=True,
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[name]))
    return name


def _child_state(cw, name: str) -> str | None:
    described = cw.describe_alarms(AlarmNames=[name], AlarmTypes=["MetricAlarm"]).get(
        "MetricAlarms", []
    )
    return described[0]["StateValue"] if described else None


def _alarm(cw, name: str, alarm_type: str) -> dict[str, Any]:
    """The one described alarm of ``alarm_type`` (MetricAlarm or CompositeAlarm) named ``name``."""
    described = cw.describe_alarms(AlarmNames=[name], AlarmTypes=[alarm_type])[f"{alarm_type}s"]
    assert len(described) == 1, f"DescribeAlarms must return {name} once, got {described!r}"
    return described[0]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


# ===== shared helpers =====
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
    ctx, probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
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
    """Poll SQS until an alarm payload satisfying predicate arrives; return (matched, all seen)."""
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
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(
        f"{description} not delivered within {timeout_s}s. "
        f"Payloads seen: {[(p.get('AlarmName'), p.get('NewStateValue')) for p in seen]}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
