"""log-alarm-notification-blocked-without-sqs-queue-policy."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "log-alarm-notification-blocked-without-sqs-queue-policy"

GROUP = "alerting"

SERVICES = ["cloudwatch", "logs", "sns", "sqs"]


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:negative-delivery", "cap:c2", "cap:c4", "concern:e2e", "concern:eventing", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A log-driven alarm's SNS notifications reach the queue whose policy admits SNS but not its
    twin without one, which stays empty; granting the policy makes the same queue receive the
    alarm's notification."""
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")
    sqs = ctx.client("sqs")

    topic = _create_topic(ctx)
    good = _create_queue(ctx, "good")
    blocked = _create_queue(ctx, "blocked")
    sqs.set_queue_attributes(
        QueueUrl=good["url"], Attributes={"Policy": json.dumps(_sns_policy(good, topic))}
    )
    for q in (good, blocked):
        _subscribe(ctx, topic["arn"], q["arn"])

    group = _xname(ctx, "lg")
    logs.create_log_group(logGroupName=group, tags=_xsvc_resource_tags())
    ctx.on_cleanup(lambda: ctx.client("logs").delete_log_group(logGroupName=group))
    logs.put_retention_policy(logGroupName=group, retentionInDays=1)
    stream = _xname(ctx, "stream")
    logs.create_log_stream(logGroupName=group, logStreamName=stream)
    namespace = ctx.unique_name("Sim2Real/BlockedNotify/")
    filt = _xname(ctx, "mf")
    logs.put_metric_filter(
        logGroupName=group, filterName=filt, filterPattern="ERROR",
        metricTransformations=[{"metricName": "Errors", "metricNamespace": namespace,
                                "metricValue": "1"}],
    )
    ctx.on_cleanup(
        lambda: ctx.client("logs").delete_metric_filter(logGroupName=group, filterName=filt)
    )
    alarm = _xname(ctx, "alarm")
    cw.put_metric_alarm(
        AlarmName=alarm, Namespace=namespace, MetricName="Errors", Statistic="Sum", Period=60,
        EvaluationPeriods=1, Threshold=1.0, ComparisonOperator="GreaterThanOrEqualToThreshold",
        TreatMissingData="notBreaching", ActionsEnabled=True,
        AlarmActions=[topic["arn"]], OKActions=[topic["arn"]], Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[alarm]))

    # ---- The log line drives the alarm to ALARM (re-written each poll so no window misses it).
    deadline = time.monotonic() + 420
    state = None
    while time.monotonic() < deadline:
        logs.put_log_events(
            logGroupName=group, logStreamName=stream,
            logEvents=[{"timestamp": int(time.time() * 1000),
                        "message": f"ERROR sim2real blocked-notify probe {alarm}"}],
        )
        state = cw.describe_alarms(AlarmNames=[alarm])["MetricAlarms"][0]["StateValue"]
        if state == "ALARM":
            break
        time.sleep(20)
    assert state == "ALARM", f"the ERROR line never drove {alarm} to ALARM within 420s: {state!r}"

    # ---- Barrier 1: the good queue receives the log-driven ALARM notification.
    good_seen: list[dict[str, Any]] = []
    blocked_seen: list[dict[str, Any]] = []
    _await(ctx, good["url"], alarm, good_seen, lambda p: p.get("NewStateValue") == "ALARM", 180,
           "the policied queue receives the log-driven ALARM notification")

    # ---- Barrier 2: a second, distinct good-side delivery (forced OK).
    cw.set_alarm_state(AlarmName=alarm, StateValue="OK", StateReason="sim2real barrier 2")
    _await(ctx, good["url"], alarm, good_seen, lambda p: p.get("NewStateValue") == "OK", 180,
           "the policied queue receives the OK notification")
    assert len({p["_message_id"] for p in good_seen}) >= 2, good_seen

    # Both notifications were fanned to the blocked queue at the same instants. It stays empty.
    _drain(ctx, blocked["url"], alarm, blocked_seen, rounds=3)
    assert not blocked_seen, (
        f"the queue with NO policy for SNS received {len(blocked_seen)} notification(s) while "
        f"the policied twin received {len(good_seen)}: SNS -> SQS delivery ignored the queue "
        f"policy: {[(p.get('OldStateValue'), p.get('NewStateValue')) for p in blocked_seen]!r}"
    )
    attrs = sqs.get_queue_attributes(
        QueueUrl=blocked["url"], AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]
    assert attrs["ApproximateNumberOfMessages"] == "0", f"blocked queue holds messages: {attrs!r}"

    # ---- Repair the one broken thing; the same queue must now receive.
    sqs.set_queue_attributes(
        QueueUrl=blocked["url"], Attributes={"Policy": json.dumps(_sns_policy(blocked, topic))}
    )
    deadline = time.monotonic() + 240
    flip = "ALARM"
    while time.monotonic() < deadline and not blocked_seen:
        cw.set_alarm_state(AlarmName=alarm, StateValue=flip, StateReason="sim2real repair leg")
        flip = "OK" if flip == "ALARM" else "ALARM"
        _drain(ctx, blocked["url"], alarm, blocked_seen, rounds=4)
    assert blocked_seen, (
        "after granting sns:SendMessage on the previously-blocked queue it still received no "
        "notification within 240s -- the absence above was not caused by the policy alone"
    )
    assert all(p.get("AlarmName") == alarm for p in blocked_seen), blocked_seen


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _create_queue(ctx, kind: str) -> dict[str, str]:
    name = _xname(ctx, f"q-{kind}")
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=name, tags=_xsvc_resource_tags())["QueueUrl"]
    ctx.on_cleanup(lambda: ctx.client("sqs").delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"]["QueueArn"]
    return {"name": name, "url": url, "arn": arn}


def _create_topic(ctx) -> dict[str, str]:
    name = _xname(ctx, "topic")
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=name, Tags=_xsvc_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda: ctx.client("sns").delete_topic(TopicArn=arn))
    return {"name": name, "arn": arn}


def _subscribe(ctx, topic_arn: str, queue_arn: str) -> str:
    sub = ctx.client("sns").subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)
    arn = sub["SubscriptionArn"]
    ctx.on_cleanup(lambda: ctx.client("sns").unsubscribe(SubscriptionArn=arn))
    return arn


def _sns_policy(queue: dict[str, str], topic: dict[str, str]) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue["arn"],
            "Condition": {"ArnEquals": {"aws:SourceArn": topic["arn"]}},
        }],
    }


def _alarm_payload(raw: str) -> dict[str, Any] | None:
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


def _drain(ctx, url: str, alarm: str, seen: list, *, rounds: int) -> None:
    """Receive (long-poll) `rounds` times, recording every notification for `alarm`."""
    sqs = ctx.client("sqs")
    for _ in range(rounds):
        for m in sqs.receive_message(
                QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5).get("Messages", []):
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
            p = _alarm_payload(m.get("Body", ""))
            if p is not None and p.get("AlarmName") == alarm:
                p["_message_id"] = m["MessageId"]
                seen.append(p)


def _await(ctx, url: str, alarm: str, seen: list, predicate, timeout_s: float, what: str):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        before = len(seen)
        _drain(ctx, url, alarm, seen, rounds=1)
        for p in seen[before:]:
            if predicate(p):
                return p
    raise AssertionError(
        f"{what}: not delivered within {timeout_s}s; seen "
        f"{[(p.get('OldStateValue'), p.get('NewStateValue')) for p in seen]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
