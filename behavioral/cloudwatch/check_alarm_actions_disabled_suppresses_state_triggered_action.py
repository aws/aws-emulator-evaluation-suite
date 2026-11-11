"""alarm-actions-disabled-suppresses-state-triggered-action."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "alarm-actions-disabled-suppresses-state-triggered-action"
GROUP = "server-side"
SERVICES = ["cloudwatch"]


@tags("axis:negative-delivery", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """DisableAlarmActions suppresses action delivery on SetAlarmState; EnableAlarmActions restores it.

    Absence is held for a window calibrated from this run's own delivery latency and checked two
    ways; restoration is then confirmed by contrast, the first notification since being the restored one.
    """
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
    sqs.set_queue_attributes(QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)})

    sns = ctx.client("sns")
    sub = sns.subscribe(TopicArn=topic["arn"], Protocol="sqs", Endpoint=queue["arn"])
    ctx.on_cleanup(lambda arn=sub["SubscriptionArn"]: ctx.client("sns").unsubscribe(SubscriptionArn=arn))

    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-behav-actalarm-")
    namespace = ctx.unique_name("Sim2RealBehavActions")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName="Errors",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        AlarmActions=[topic["arn"]],
        TreatMissingData="missing",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    # 0. Positive control: actions start enabled by default. Force a transition and confirm
    #    delivery, timing it — this proves the wiring works before ActionsEnabled is touched at
    #    all, and gives a measured latency to size the absence window against.
    baseline_start = time.monotonic()
    cw.set_alarm_state(
        AlarmName=alarm_name, StateValue="ALARM", StateReason="behavioral-check-baseline"
    )
    baseline = _wait_for_messages(ctx, queue["url"], expected_count=1, timeout_s=90.0)
    baseline_latency_s = time.monotonic() - baseline_start
    assert len(baseline) == 1, f"expected the baseline transition to deliver one notification, got {baseline}"
    baseline_payload = json.loads(baseline[0]["body"]["Message"])
    assert baseline_payload["AlarmName"] == alarm_name, (
        f"baseline notification named the wrong alarm: expected {alarm_name}, got {baseline_payload.get('AlarmName')}"
    )

    absence_window_s = max(60.0, 3.0 * baseline_latency_s)
    cw.set_alarm_state(AlarmName=alarm_name, StateValue="OK", StateReason="behavioral-check-reset")

    # 1. Disable actions and force a *fresh* transition into ALARM: no notification should be
    #    delivered within >=3x the latency the positive control just measured on this same wiring.
    cw.disable_alarm_actions(AlarmNames=[alarm_name])
    described = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]
    assert described["ActionsEnabled"] is False, "DisableAlarmActions did not flip ActionsEnabled to false"

    cw.set_alarm_state(
        AlarmName=alarm_name, StateValue="ALARM", StateReason="behavioral-check-suppressed"
    )
    suppressed = _drain_queue(ctx, queue["url"], max_wait_s=absence_window_s)
    assert suppressed == [], (
        f"expected no SNS notification while alarm actions were disabled, got {suppressed}"
    )
    depth = _queue_depth(ctx, queue["url"])
    assert depth == 0, f"queue reports {depth} message(s) still pending after the withheld transition"

    # 2. Re-enable actions, force a *fresh* transition, and expect its notification to be the only
    #    one delivered since the baseline: a suppressed transition's, sent first, would precede it.
    cw.enable_alarm_actions(AlarmNames=[alarm_name])
    described = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]
    assert described["ActionsEnabled"] is True, "EnableAlarmActions did not flip ActionsEnabled to true"

    cw.set_alarm_state(AlarmName=alarm_name, StateValue="OK", StateReason="behavioral-check-reset-2")
    cw.set_alarm_state(
        AlarmName=alarm_name, StateValue="ALARM", StateReason="behavioral-check-restored"
    )
    delivered = _wait_for_reason(ctx, queue["url"], "behavioral-check-restored", timeout_s=90.0)
    reasons = [_reason(m) for m in delivered]
    assert reasons == ["behavioral-check-restored"], (
        f"expected no SNS notification while alarm actions were disabled and exactly one once they "
        f"were re-enabled; notifications since the baseline had reasons {reasons}"
    )
    payload = json.loads(delivered[0]["body"]["Message"])
    assert payload["AlarmName"] == alarm_name, (
        f"restored notification named the wrong alarm: expected {alarm_name}, got {payload.get('AlarmName')}"
    )
    assert payload["NewStateValue"] == "ALARM", (
        f"restored notification reported the wrong state: expected ALARM, got {payload.get('NewStateValue')}"
    )


def _create_queue(ctx: Any) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-actq-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _create_topic(ctx: Any) -> dict[str, str]:
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-acttopic-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return {"arn": arn}


def _deadline(ctx: Any, seconds: float) -> float:
    """A monotonic deadline of `seconds`, capped by the run's remaining budget."""
    left = ctx.time_left()
    return time.monotonic() + (seconds if left is None else min(seconds, left))


def _receive(sqs: Any, queue_url: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
    for msg in resp.get("Messages", []):
        try:
            body = json.loads(msg["Body"])
        except (ValueError, TypeError):
            body = msg["Body"]
        out.append({"body": body, "message_id": msg["MessageId"]})
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _drain_queue(ctx: Any, queue_url: str, *, max_wait_s: float) -> list[dict[str, Any]]:
    """Every message received over a fixed window, used to hold an absence."""
    sqs = ctx.client("sqs")
    out: list[dict[str, Any]] = []
    deadline = _deadline(ctx, max_wait_s)
    while time.monotonic() < deadline:
        out.extend(_receive(sqs, queue_url))
    return out


def _queue_depth(ctx: Any, queue_url: str) -> int:
    """ApproximateNumberOfMessages, as an independent observable alongside an empty receive."""
    sqs = ctx.client("sqs")
    attrs = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]
    return int(attrs["ApproximateNumberOfMessages"])


def _wait_for_reason(ctx: Any, queue_url: str, reason: str, *, timeout_s: float) -> list[dict[str, Any]]:
    """Every notification received up to and including the one whose NewStateReason is `reason`."""
    sqs = ctx.client("sqs")
    out: list[dict[str, Any]] = []
    deadline = _deadline(ctx, timeout_s)
    while time.monotonic() < deadline:
        out.extend(_receive(sqs, queue_url))
        if any(_reason(m) == reason for m in out):
            return out
    raise AssertionError(
        f"no notification with reason {reason!r} within {timeout_s}s; got reasons {[_reason(m) for m in out]}"
    )


def _reason(msg: dict[str, Any]) -> Any:
    try:
        return json.loads(msg["body"]["Message"]).get("NewStateReason")
    except (KeyError, TypeError, ValueError):
        return None


def _wait_for_messages(ctx: Any, queue_url: str, *, expected_count: int, timeout_s: float) -> list[dict[str, Any]]:
    sqs = ctx.client("sqs")
    out: list[dict[str, Any]] = []
    deadline = _deadline(ctx, timeout_s)
    while len(out) < expected_count and time.monotonic() < deadline:
        out.extend(_receive(sqs, queue_url))
    if len(out) < expected_count:
        raise AssertionError(f"expected {expected_count} messages, got {len(out)} within {timeout_s}s")
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
