"""metric-filter-default-value-publishes-zero-only-for-ingested-non-matching-events."""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags

CHECK = "metric-filter-default-value-publishes-zero-only-for-ingested-non-matching-events"

GROUP = "alerting"

SERVICES = ["cloudwatch", "logs", "sns", "sqs"]

_METRIC = "Errors"
#: A ceiling for the filters' datapoints to become readable; never asserted as a latency.
_METRIC_DEADLINE_S = 300.0


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing",
      "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A metric filter's defaultValue=0 publishes 0 for an ingested non-matching line and nothing for
    a minute with no ingested events, while a no-default twin publishes only the matching line; the
    alarm on the filtered metric notifies SNS -> SQS naming that metric.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/MonitoringLogData.html
    """
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")
    topic, queue = _topic_to_queue(ctx)

    primary = _filtered_alarm(ctx, topic["arn"], default_value=0.0, kind="dv")
    control = _filtered_alarm(ctx, topic["arn"], default_value=None, kind="ctl")
    inbox = _Inbox(ctx, queue["url"])

    # ---- The alarm action: an ALARM transition of the filtered metric's alarm reaches the queue.
    cw.set_alarm_state(AlarmName=primary["alarm"], StateValue="ALARM",
                       StateReason="sim2real: filtered metric breach")
    p_fire = _await_note(inbox, primary["alarm"], None, "ALARM", 180)
    assert (p_fire["Trigger"].get("Namespace"), p_fire["Trigger"].get("MetricName")) == (
        primary["namespace"], _METRIC), p_fire["Trigger"]

    # ---- One ERROR line, two empty minutes, then one non-matching line, each stamped explicitly.
    base = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    err_minute, info_minute = base - timedelta(minutes=5), base - timedelta(minutes=2)
    for a in (primary, control):
        _write(logs, a, f"ERROR sim2real default-value probe {a['alarm']}",
               err_minute + timedelta(seconds=10))
        _write(logs, a, f"info sim2real healthy heartbeat {a['alarm']}",
               info_minute + timedelta(seconds=10))
    t0 = err_minute - timedelta(minutes=2)

    p_dps = _poll(lambda: _datapoints(cw, primary["namespace"], t0), lambda d: len(d) >= 2,
                  _METRIC_DEADLINE_S, "the defaultValue filter's datapoints readable")
    got = [(d["Timestamp"], d["Sum"]) for d in p_dps]
    assert got == [(err_minute, 1.0), (info_minute, 0.0)], (
        f"the defaultValue=0 metric must hold Sum 1 for the ERROR minute and Sum 0 for the "
        f"non-matching line's minute, and nothing for the two empty minutes between: {got!r}"
    )
    assert [d["SampleCount"] for d in p_dps] == [1.0, 1.0], f"one event per minute: {p_dps!r}"

    # The twin's lines were ingested with the primary's; once its ERROR minute is readable, its
    # non-matching line has published nothing.
    c_dps = _poll(lambda: _datapoints(cw, control["namespace"], t0),
                  lambda d: any(x["Timestamp"] == err_minute for x in d), _METRIC_DEADLINE_S,
                  "the no-default filter's ERROR datapoint readable")
    assert [(d["Timestamp"], d["Sum"]) for d in c_dps] == [(err_minute, 1.0)], (
        f"the no-default metric must hold only the ERROR minute's datapoint, got {c_dps!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _write(logs, a: dict[str, str], message: str, at: datetime) -> None:
    resp = logs.put_log_events(
        logGroupName=a["group"], logStreamName=a["stream"],
        logEvents=[{"timestamp": int(at.timestamp() * 1000), "message": message}],
    )
    assert not resp.get("rejectedLogEventsInfo"), (
        f"line for {a['group']} was rejected: {resp.get('rejectedLogEventsInfo')!r}"
    )


def _filtered_alarm(ctx, topic_arn: str, *, default_value, kind: str) -> dict[str, str]:
    """Log group + stream + ERROR metric filter (no dimensions) + alarm on that exact metric."""
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")
    group = _xname(ctx, f"lg-{kind}")
    logs.create_log_group(logGroupName=group, tags=_xsvc_resource_tags())
    ctx.on_cleanup(lambda: ctx.client("logs").delete_log_group(logGroupName=group))
    logs.put_retention_policy(logGroupName=group, retentionInDays=1)
    stream = _xname(ctx, "stream")
    logs.create_log_stream(logGroupName=group, logStreamName=stream)
    ctx.on_cleanup(
        lambda: ctx.client("logs").delete_log_stream(logGroupName=group, logStreamName=stream)
    )

    namespace = ctx.unique_name(f"Sim2Real/DefaultValue/{kind}/")
    tx: dict[str, Any] = {"metricName": _METRIC, "metricNamespace": namespace, "metricValue": "1"}
    if default_value is not None:
        tx["defaultValue"] = default_value
    filt = _xname(ctx, f"mf-{kind}")
    logs.put_metric_filter(
        logGroupName=group, filterName=filt, filterPattern="ERROR", metricTransformations=[tx]
    )
    ctx.on_cleanup(
        lambda: ctx.client("logs").delete_metric_filter(logGroupName=group, filterName=filt)
    )
    echoed = logs.describe_metric_filters(
        logGroupName=group, filterNamePrefix=filt
    )["metricFilters"][0]["metricTransformations"][0]
    assert echoed.get("defaultValue") == default_value, (
        f"filter {filt} echoed defaultValue {echoed.get('defaultValue')!r}, set {default_value!r}"
    )

    alarm = _xname(ctx, f"alarm-{kind}")
    cw.put_metric_alarm(
        AlarmName=alarm, Namespace=namespace, MetricName=_METRIC, Statistic="Sum", Period=60,
        EvaluationPeriods=1, Threshold=1.0, ComparisonOperator="GreaterThanOrEqualToThreshold",
        TreatMissingData="missing", ActionsEnabled=True,
        AlarmActions=[topic_arn], OKActions=[topic_arn], Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[alarm]))
    return {"group": group, "stream": stream, "namespace": namespace, "filter": filt,
            "alarm": alarm}


def _create_queue(ctx) -> dict[str, str]:
    name = _xname(ctx, "q")
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


def _topic_to_queue(ctx) -> tuple[dict, dict]:
    """SNS topic + SQS queue subscribed to it, with the queue policy SNS needs."""
    topic = _create_topic(ctx)
    queue = _create_queue(ctx)
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue["arn"],
            "Condition": {"ArnEquals": {"aws:SourceArn": topic["arn"]}},
        }],
    }
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)}
    )
    sub = ctx.client("sns").subscribe(TopicArn=topic["arn"], Protocol="sqs", Endpoint=queue["arn"])
    ctx.on_cleanup(lambda: ctx.client("sns").unsubscribe(SubscriptionArn=sub["SubscriptionArn"]))
    return topic, queue


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


class _Inbox:
    """Drains the queue and keeps every alarm notification seen, with its SQS MessageId."""

    def __init__(self, ctx, url: str) -> None:
        self._sqs = ctx.client("sqs")
        self._url = url
        self.items: list[dict[str, Any]] = []

    def drain(self) -> None:
        while True:
            msgs = self._sqs.receive_message(
                QueueUrl=self._url, MaxNumberOfMessages=10, WaitTimeSeconds=2
            ).get("Messages", [])
            if not msgs:
                return
            for m in msgs:
                self._sqs.delete_message(QueueUrl=self._url, ReceiptHandle=m["ReceiptHandle"])
                p = _alarm_payload(m.get("Body", ""))
                if p is not None:
                    p["_message_id"] = m["MessageId"]
                    self.items.append(p)

    def find(self, alarm: str, *, new: str, old: str | None = None) -> dict[str, Any] | None:
        for p in self.items:
            if p.get("AlarmName") == alarm and p.get("NewStateValue") == new and (
                    old is None or p.get("OldStateValue") == old):
                return p
        return None

    def summary(self) -> list[tuple]:
        return [(p.get("AlarmName"), p.get("OldStateValue"), p.get("NewStateValue"))
                for p in self.items]


def _await_note(inbox: _Inbox, alarm: str, old: str | None, new: str, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        inbox.drain()
        hit = inbox.find(alarm, old=old, new=new)
        if hit is not None:
            return hit
        time.sleep(3)
    raise AssertionError(
        f"no {old} -> {new} notification for {alarm} within {timeout_s}s: {inbox.summary()!r}"
    )


def _poll(probe, predicate, timeout_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(5)
    raise AssertionError(f"{description}: not met within {timeout_s}s, last {last!r}")


def _datapoints(cw, namespace: str, start: datetime) -> list[dict[str, Any]]:
    dps = cw.get_metric_statistics(
        Namespace=namespace, MetricName=_METRIC, StartTime=start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=1), Period=60,
        Statistics=["Sum", "SampleCount"],
    )["Datapoints"]
    return sorted(dps, key=lambda d: d["Timestamp"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
