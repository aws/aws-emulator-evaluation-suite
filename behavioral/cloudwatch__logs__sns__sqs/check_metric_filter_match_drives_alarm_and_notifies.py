"""metric-filter-match-drives-alarm-and-notifies."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "metric-filter-match-drives-alarm-and-notifies"

GROUP = "alerting"

SERVICES = ["cloudwatch", "logs", "sns", "sqs"]


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:metrics", "concern:representation", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A log line matching a metric filter (no defaultValue) becomes a datapoint that drives an
    alarm to ALARM by evaluation, and the SNS notification in the queue names the filter's namespace
    and metric with statistic Sum."""
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
                # No defaultValue: a non-matching event must publish NOTHING.
            }
        ],
    )
    ctx.on_cleanup(
        lambda: ctx.client("logs").delete_metric_filter(
            logGroupName=group_name, filterName=filter_name
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

    def _emit_and_state() -> str:
        logs.put_log_events(
            logGroupName=group_name,
            logStreamName=stream_name,
            logEvents=[
                {
                    "timestamp": int(time.time() * 1000),
                    "message": f"ERROR sim2real metric-filter probe {marker}",
                }
            ],
        )
        return cw.describe_alarms(AlarmNames=[alarm])["MetricAlarms"][0]["StateValue"]

    state = _poll_until(
        _emit_and_state,
        lambda s: s == "ALARM",
        timeout_s=420,
        interval_s=20.0,
        description=(
            f"a log line matching filter {filter_name} drives {alarm} to ALARM via "
            f"{namespace}/{metric_name}"
        ),
    )
    assert state == "ALARM", (
        f"the metric-filter datapoint must be visible to the alarm evaluator; {alarm} is {state!r}"
    )

    payload, _ = _await_payload(
        ctx,
        queue["url"],
        lambda p: p.get("AlarmName") == alarm and p.get("NewStateValue") == "ALARM",
        timeout_s=180,
        description=f"notification for the log-driven ALARM transition of {alarm}",
    )
    # The notification must attribute the alarm to the FILTER's metric, not to some synthetic one.
    trigger = payload.get("Trigger", {})
    assert trigger.get("Namespace") == namespace, (
        f"Trigger.Namespace must be the metric filter's namespace, got {trigger!r}"
    )
    assert trigger.get("MetricName") == metric_name, (
        f"Trigger.MetricName must be the metric filter's metric, got {trigger!r}"
    )
    assert str(trigger.get("Statistic", "")).upper() == "SUM", trigger

    # The filter must still be attached and unchanged -- the pipeline is durable, not one-shot.
    described = logs.describe_metric_filters(
        logGroupName=group_name, filterNamePrefix=filter_name
    )["metricFilters"]
    assert described, f"metric filter {filter_name} must still be attached to {group_name}"
    transformation = described[0]["metricTransformations"][0]
    assert transformation["metricName"] == metric_name, transformation
    assert transformation["metricNamespace"] == namespace, transformation
    assert "defaultValue" not in transformation, (
        f"the filter was created without a defaultValue and must not acquire one, got "
        f"{transformation!r}"
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
