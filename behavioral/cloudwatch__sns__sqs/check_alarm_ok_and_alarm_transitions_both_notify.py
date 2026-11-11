"""alarm-ok-and-alarm-transitions-both-notify."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "alarm-ok-and-alarm-transitions-both-notify"

GROUP = "alerting"

SERVICES = ["cloudwatch", "sns", "sqs"]


def _topic_to_queue(ctx) -> tuple[dict, dict]:
    """Create an SNS topic + an SQS queue subscribed to it (with the queue policy SNS needs).

    Returns (topic, queue) dicts. Cleanup is tracked LIFO by the create_* helpers + on_cleanup.
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
    sqs.set_queue_attributes(
        QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)}
    )
    sns = ctx.client("sns")
    sub = sns.subscribe(TopicArn=topic["arn"], Protocol="sqs", Endpoint=queue["arn"])
    ctx.on_cleanup(
        lambda: ctx.client("sns").unsubscribe(SubscriptionArn=sub["SubscriptionArn"])
    )
    return topic, queue


def _put_alarm(ctx, topic_arn: str, *, ok_action: bool = False) -> str:
    """Create a metric alarm whose AlarmActions (and optionally OKActions) publish to the topic.

    The metric is a private namespace/name that is never fed data — state is driven with
    SetAlarmState, so the threshold/period values only need to be well-formed.
    """
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("alarm-")
    kwargs = dict(
        AlarmName=name,
        MetricName="probe-metric",
        Namespace="SimParity/CrossService",
        Statistic="Sum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanOrEqualToThreshold",
        ActionsEnabled=True,
        AlarmActions=[topic_arn],
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-xsvc"},
        ],
    )
    if ok_action:
        kwargs["OKActions"] = [topic_arn]
    cw.put_metric_alarm(**kwargs)
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[name]))
    return name


def _alarm_notifications(ctx, queue_url: str, expected: int) -> list[dict]:
    """Collect `expected` SNS->SQS notifications and return the parsed alarm payloads.

    SNS default (non-raw) delivery wraps the alarm JSON in an SNS envelope; envelope["Message"]
    is itself a JSON string of the CloudWatch alarm notification.
    """
    msgs = _wait_for_messages(ctx, queue_url, expected_count=expected, timeout_s=90)
    payloads = []
    for m in msgs:
        envelope = m["body"]
        assert isinstance(envelope, dict) and envelope.get("Type") == "Notification", (
            f"expected SNS envelope, got {envelope!r}"
        )
        payloads.append(json.loads(envelope["Message"]))
    return payloads


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "concern:metrics",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """With both AlarmActions and OKActions on the topic, driving ALARM then OK publishes a
    notification for EACH transition (the alarm-state-machine both directions), and only on a
    state CHANGE — a repeated same-state SetAlarmState does not re-notify."""
    topic, queue = _topic_to_queue(ctx)
    name = _put_alarm(ctx, topic["arn"], ok_action=True)
    cw = ctx.client("cloudwatch")
    # Alarm starts INSUFFICIENT_DATA; ALARM and OK are two distinct state changes.
    cw.set_alarm_state(AlarmName=name, StateValue="ALARM", StateReason="probe: ALARM")
    cw.set_alarm_state(
        AlarmName=name, StateValue="ALARM", StateReason="probe: ALARM again (no-op)"
    )
    cw.set_alarm_state(AlarmName=name, StateValue="OK", StateReason="probe: OK")

    start = time.monotonic()
    payloads = _alarm_notifications(ctx, queue["url"], expected=2)
    positive_latency_s = time.monotonic() - start
    states = sorted(p.get("NewStateValue") for p in payloads)
    assert states == ["ALARM", "OK"], (
        f"expected one ALARM + one OK notification, got {states}"
    )
    assert all(p.get("AlarmName") == name for p in payloads), (
        "notification for wrong alarm"
    )

    # The no-op ALARM->ALARM call must not have queued a third notification behind the two
    # already collected. Hold the window at >=3x the observed positive-control latency (never a
    # bare sleep) and read the same queue independently: a target that fires on every
    # SetAlarmState call, not just on a state CHANGE, leaks its extra notification here.
    leaked = _drain(ctx, queue["url"], window_s=max(30.0, positive_latency_s * 3))
    assert not leaked, (
        f"repeated same-state SetAlarmState (ALARM->ALARM no-op) re-notified: {leaked}"
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


def _wait_for_messages(ctx, queue_url, expected_count=1, timeout_s=60.0, delete=True):
    """Poll SQS until expected_count messages arrive; return them (raises on timeout)."""
    sqs = ctx.client("sqs")
    messages: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while len(messages) < expected_count and time.monotonic() < deadline:
        remaining = max(1, int(deadline - time.monotonic()))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=min(10, expected_count - len(messages)),
            WaitTimeSeconds=min(5, remaining),
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            messages.append(
                {
                    "body": body,
                    "message_id": msg["MessageId"],
                    "receipt_handle": msg["ReceiptHandle"],
                    "attributes": msg.get("MessageAttributes", {}),
                }
            )
            if delete:
                sqs.delete_message(
                    QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"]
                )
    if len(messages) < expected_count:
        raise AssertionError(
            f"Expected {expected_count} messages, got {len(messages)} within {timeout_s}s"
        )
    return messages


def _drain(ctx, queue_url: str, window_s: float) -> list[str]:
    """Poll SQS for the full window and return every message body seen (deleted as consumed).

    Used as an absence check: an empty return means nothing arrived in the window, never a
    guess based on how long a single `receive_message` call happened to wait.
    """
    sqs = ctx.client("sqs")
    bodies: list[str] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        remaining = max(1, int(deadline - time.monotonic()))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=min(5, remaining),
        )
        for msg in resp.get("Messages", []):
            bodies.append(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return bodies


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
