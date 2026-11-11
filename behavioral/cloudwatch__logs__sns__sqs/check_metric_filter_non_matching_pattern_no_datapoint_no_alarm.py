"""metric-filter-non-matching-pattern-no-datapoint-no-alarm."""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags

CHECK = "metric-filter-non-matching-pattern-no-datapoint-no-alarm"

GROUP = "alerting"

SERVICES = ["cloudwatch", "logs", "sns", "sqs"]


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags(
    "axis:negative-delivery",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """Log events that do not match a metric filter publish no datapoint, so its alarm stays out of
    ALARM and nothing is notified; a twin filter matching those lines is the barrier, and one later
    matching line fires the same alarm and notification as the control.
    """
    topic, queue = _topic_to_queue(ctx)
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")

    group_name, stream_name = _log_group_with_stream(ctx)
    namespace = _xname(ctx, "ns")
    metric_name = "FilteredErrors"
    filter_name = _xname(ctx, "filter")
    logs.put_metric_filter(
        logGroupName=group_name,
        filterName=filter_name,
        filterPattern="ERROR",
        metricTransformations=[
            {
                "metricName": metric_name,
                "metricNamespace": namespace,
                "metricValue": "1",
                # No defaultValue: with one, a non-matching event legitimately publishes a 0.
            }
        ],
    )
    ctx.on_cleanup(
        lambda: ctx.client("logs").delete_metric_filter(
            logGroupName=group_name, filterName=filter_name
        )
    )

    # Twin filter on the same group matching the healthy lines: its datapoint is the barrier.
    twin_metric = "HealthyLines"
    twin_filter = _xname(ctx, "filter")
    logs.put_metric_filter(
        logGroupName=group_name,
        filterName=twin_filter,
        filterPattern="INFO",
        metricTransformations=[
            {"metricName": twin_metric, "metricNamespace": namespace, "metricValue": "1"}
        ],
    )
    ctx.on_cleanup(
        lambda: ctx.client("logs").delete_metric_filter(
            logGroupName=group_name, filterName=twin_filter
        )
    )

    alarm = _xname(ctx, "alarm")
    cw.put_metric_alarm(
        AlarmName=alarm,
        Namespace=namespace,
        MetricName=metric_name,
        Statistic="Sum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanOrEqualToThreshold",
        TreatMissingData="notBreaching",
        ActionsEnabled=True,
        AlarmActions=[topic["arn"]],
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[alarm]))

    marker = ctx.unique_name("probe-")
    quiet_lines = [
        f"INFO request handled {marker}",
        f"WARN slow response {marker}",
        f"DEBUG cache warm {marker}",
        f"INFO error_count=0 {marker}",
    ]

    def _emit(messages: list[str]) -> None:
        now_ms = int(time.time() * 1000)
        logs.put_log_events(
            logGroupName=group_name,
            logStreamName=stream_name,
            logEvents=[
                {"timestamp": now_ms + i, "message": m} for i, m in enumerate(messages)
            ],
        )

    # Absence by contrast: once the twin filter has counted the healthy lines of the same batch,
    # the 'ERROR' filter has evaluated them too.
    _emit(quiet_lines)
    _poll_until(
        lambda: _metric_sums(cw, namespace, twin_metric),
        lambda p: sum(p) >= 2.0,
        timeout_s=240,
        interval_s=2.0,
        description=f"the twin filter 'INFO' publishing its datapoint for the lines in {group_name}",
    )

    # (1) No datapoint may exist at all for the filter's metric.
    datapoints = _metric_sums(cw, namespace, metric_name)
    assert not datapoints, (
        f"a metric filter with filterPattern 'ERROR' and no defaultValue must publish NOTHING for "
        f"non-matching events, but {namespace}/{metric_name} has datapoints {datapoints!r}"
    )
    # (2) The alarm stays out of ALARM while only non-matching events have been written.
    state = cw.describe_alarms(AlarmNames=[alarm])["MetricAlarms"][0]["StateValue"]
    assert state != "ALARM", (
        f"{alarm} is in ALARM although only events NOT matching filterPattern 'ERROR' were written "
        f"to {group_name}"
    )

    # (3) + control: one MATCHING line, on the same wiring.
    def _emit_match_and_state() -> str:
        _emit([f"ERROR sim2real metric-filter probe {marker}"])
        return cw.describe_alarms(AlarmNames=[alarm])["MetricAlarms"][0]["StateValue"]

    state = _poll_until(
        _emit_match_and_state,
        lambda s: s == "ALARM",
        timeout_s=360,
        interval_s=20.0,
        description=f"a MATCHING log line drives {alarm} to ALARM",
    )
    assert state == "ALARM", (
        f"the control must fire, proving the silence above came from filterPattern selectivity and "
        f"not from broken wiring; {alarm} is {state!r}"
    )
    matched_points = _metric_sums(cw, namespace, metric_name)
    assert matched_points, (
        f"the matching event must publish a datapoint to {namespace}/{metric_name}, got none"
    )

    payload, seen = _await_payload(
        ctx,
        queue["url"],
        lambda p: p.get("AlarmName") == alarm and p.get("NewStateValue") == "ALARM",
        timeout_s=180,
        description=f"notification for the matching log line that drove {alarm} to ALARM",
    )
    assert payload["OldStateValue"] in {"OK", "INSUFFICIENT_DATA"}, (
        f"the delivered transition must come from a non-ALARM state, got OldStateValue="
        f"{payload.get('OldStateValue')!r}"
    )
    early = [p for p in seen if p is not payload]
    assert not early, (
        f"no notification may be delivered before the first MATCHING log event, but "
        f"{len(early)} arrived first: "
        f"{[(p.get('AlarmName'), p.get('NewStateValue')) for p in early]}"
    )


def _metric_sums(cw, namespace: str, metric_name: str) -> list[float]:
    """Sum datapoints for the filter's metric over the last 15 minutes (empty list = none)."""
    now = datetime.now(timezone.utc)
    resp = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric_name,
        StartTime=now - timedelta(minutes=15),
        EndTime=now + timedelta(minutes=1),
        Period=60,
        Statistics=["Sum"],
    )
    return [float(p["Sum"]) for p in resp.get("Datapoints", [])]


# ===== helpers =====
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


def _log_group_with_stream(ctx) -> tuple[str, str]:
    """Create a log group (1-day retention, tagged) plus a stream. Returns (group, stream)."""
    logs = ctx.client("logs")
    group_name = _xname(ctx, "lg")
    logs.create_log_group(logGroupName=group_name, tags=_xsvc_resource_tags())
    ctx.on_cleanup(lambda: ctx.client("logs").delete_log_group(logGroupName=group_name))
    # Bound stored-data cost even if teardown is interrupted.
    logs.put_retention_policy(logGroupName=group_name, retentionInDays=1)
    stream_name = _xname(ctx, "stream")
    logs.create_log_stream(logGroupName=group_name, logStreamName=stream_name)
    return group_name, stream_name


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
    raise AssertionError(
        f"{description} not delivered within {timeout_s}s. "
        f"Payloads seen: {[(p.get('AlarmName'), p.get('NewStateValue')) for p in seen]}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
