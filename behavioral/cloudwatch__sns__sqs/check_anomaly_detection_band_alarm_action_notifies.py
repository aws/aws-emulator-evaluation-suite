"""anomaly-detection-band-alarm-action-notifies."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "anomaly-detection-band-alarm-action-notifies"

GROUP = "alerting"

SERVICES = ["cloudwatch", "sns", "sqs"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing", "concern:metrics", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An ANOMALY_DETECTION_BAND alarm round-trips its ThresholdMetricId/Metrics form, fires its
    action on ALARM, and its SNS notification carries Trigger.Metrics instead of a static Threshold.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Create_Anomaly_Detection_Alarm.html
    """
    topic, queue = _topic_to_queue(ctx)
    cw = ctx.client("cloudwatch")

    namespace = _xname(ctx, "ns")
    metric = "AnomalyMetric"
    detector = {"Namespace": namespace, "MetricName": metric, "Stat": "Average"}
    cw.put_anomaly_detector(SingleMetricAnomalyDetector=detector)
    ctx.on_cleanup(
        lambda: ctx.client("cloudwatch").delete_anomaly_detector(
            SingleMetricAnomalyDetector=detector
        )
    )

    detectors = cw.describe_anomaly_detectors(Namespace=namespace, MetricName=metric)[
        "AnomalyDetectors"
    ]
    assert detectors, (
        f"the anomaly detector for {namespace}/{metric} must be listable after "
        f"PutAnomalyDetector, got {detectors!r}"
    )

    alarm = _xname(ctx, "alarm")
    cw.put_metric_alarm(
        AlarmName=alarm,
        ComparisonOperator="LessThanLowerOrGreaterThanUpperThreshold",
        EvaluationPeriods=1,
        ThresholdMetricId="ad1",
        ActionsEnabled=True,
        AlarmActions=[topic["arn"]],
        Metrics=[
            {
                "Id": "m1",
                "MetricStat": {
                    "Metric": {"Namespace": namespace, "MetricName": metric},
                    "Period": 60,
                    "Stat": "Average",
                },
                "ReturnData": True,
            },
            {
                "Id": "ad1",
                "Expression": "ANOMALY_DETECTION_BAND(m1, 2)",
                "ReturnData": True,
            },
        ],
        Tags=_xsvc_tags_kv(),
    )
    # Registered after the detector so LIFO deletes the alarm first: CloudWatch refuses to delete
    # a detector still referenced by an alarm.
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[alarm]))

    # --- the alarm definition must round-trip in its math form, not be flattened ---
    described = cw.describe_alarms(AlarmNames=[alarm])["MetricAlarms"][0]
    assert described.get("ThresholdMetricId") == "ad1", (
        f"an anomaly-detection alarm is thresholded by ThresholdMetricId, which must round-trip; "
        f"got {described.get('ThresholdMetricId')!r}"
    )
    assert described.get("Threshold") is None, (
        f"Threshold and ThresholdMetricId are mutually exclusive -- an anomaly-detection alarm "
        f"must not report a static Threshold, got {described.get('Threshold')!r}"
    )
    by_id = {m["Id"]: m for m in described.get("Metrics", [])}
    assert set(by_id) == {"m1", "ad1"}, (
        f"the Metrics array must round-trip both the source metric and the band expression, got "
        f"ids {sorted(by_id)}"
    )
    assert by_id["ad1"].get("Expression") == "ANOMALY_DETECTION_BAND(m1, 2)", (
        f"the band expression must round-trip verbatim, got {by_id['ad1'].get('Expression')!r}"
    )
    assert (
        by_id["m1"]["MetricStat"]["Metric"]["MetricName"] == metric
    ), by_id["m1"]

    # --- the action must fire on the transition, exactly like a static-threshold alarm ---
    # Forced state: a detector needs days of metric history before it produces a band.
    cw.set_alarm_state(
        AlarmName=alarm,
        StateValue="ALARM",
        StateReason="probe: forced ALARM on the anomaly-detection alarm",
    )
    payload, _ = _await_payload(
        ctx,
        queue["url"],
        lambda p: p.get("AlarmName") == alarm,
        timeout_s=180,
        description=f"notification for the anomaly-detection alarm {alarm}",
    )
    assert payload["NewStateValue"] == "ALARM", payload
    assert alarm in payload.get("AlarmArn", ""), payload.get("AlarmArn")

    # --- the delivered representation must be the math form ---
    trigger = payload.get("Trigger")
    assert isinstance(trigger, dict), (
        f"the notification must carry a Trigger describing the alarm, got {trigger!r}"
    )
    trigger_metrics = trigger.get("Metrics")
    assert isinstance(trigger_metrics, list) and trigger_metrics, (
        f"Trigger.Metrics must carry the alarm's metric-math definition for an anomaly-detection "
        f"alarm (consumers cannot read Trigger.Threshold here), got {trigger!r}"
    )
    trigger_ids = {m.get("Id") for m in trigger_metrics if isinstance(m, dict)}
    assert {"m1", "ad1"} <= trigger_ids, (
        f"Trigger.Metrics must name both the source metric and the band expression, got ids "
        f"{sorted(i for i in trigger_ids if i)}"
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
