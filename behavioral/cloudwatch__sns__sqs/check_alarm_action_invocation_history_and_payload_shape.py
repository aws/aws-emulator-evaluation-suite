"""alarm-action-invocation-history-and-payload-shape."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "alarm-action-invocation-history-and-payload-shape"

GROUP = "alerting"

SERVICES = ["cloudwatch", "sns", "sqs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:metrics", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An alarm action fired by SetAlarmState delivers a notification with the documented fields and
    the full Trigger block (metric, namespace, statistic, comparison, threshold, period,
    dimensions), and DescribeAlarmHistory records an Action item naming the invoked topic."""
    topic, queue = _topic_to_queue(ctx)
    account = topic["arn"].split(":")[4]
    cw = ctx.client("cloudwatch")

    description = "sim2real alarm-action representation probe"
    dim_value = ctx.unique_name("probe-dim-")
    alarm = _xname(ctx, "alarm")
    cw.put_metric_alarm(
        AlarmName=alarm,
        AlarmDescription=description,
        MetricName="probe-metric",
        Namespace="SimParity/CrossService",
        Dimensions=[{"Name": "ProbeId", "Value": dim_value}],
        Statistic="Sum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanOrEqualToThreshold",
        ActionsEnabled=True,
        AlarmActions=[topic["arn"]],
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[alarm]))

    cw.set_alarm_state(
        AlarmName=alarm,
        StateValue="ALARM",
        StateReason="probe: forced ALARM for action representation",
    )

    payload, _ = _await_payload(
        ctx,
        queue["url"],
        lambda p: p.get("AlarmName") == alarm,
        timeout_s=180,
        description=f"alarm notification for {alarm}",
    )

    # --- envelope-level fields every consumer keys off ---
    assert payload["NewStateValue"] == "ALARM", payload
    assert payload["OldStateValue"] == "INSUFFICIENT_DATA", (
        f"a never-fed alarm starts INSUFFICIENT_DATA, so the first transition must report "
        f"OldStateValue=INSUFFICIENT_DATA, got {payload.get('OldStateValue')!r}"
    )
    assert payload["AlarmDescription"] == description, (
        f"AlarmDescription must round-trip into the notification, got "
        f"{payload.get('AlarmDescription')!r}"
    )
    assert payload["AWSAccountId"] == account, (
        f"AWSAccountId={payload.get('AWSAccountId')!r}, expected {account!r}"
    )
    assert alarm in payload.get("AlarmArn", ""), (
        f"AlarmArn must name the alarm, got {payload.get('AlarmArn')!r}"
    )
    # Real CloudWatch reports Region as a human-readable name ("US East (N. Virginia)"), so only
    # its presence is contractual, not its equality with ctx.region.
    assert isinstance(payload.get("Region"), str) and payload["Region"], (
        f"Region must be a non-empty string, got {payload.get('Region')!r}"
    )
    assert isinstance(payload.get("StateChangeTime"), str) and payload["StateChangeTime"], (
        f"StateChangeTime must be a non-empty string, got {payload.get('StateChangeTime')!r}"
    )

    # --- the Trigger block: the alarm definition as-evaluated ---
    trigger = payload.get("Trigger")
    assert isinstance(trigger, dict), (
        f"the notification must carry a Trigger object describing the evaluated metric, got "
        f"{trigger!r}"
    )
    assert trigger["MetricName"] == "probe-metric", trigger
    assert trigger["Namespace"] == "SimParity/CrossService", trigger
    # CloudWatch emits the statistic upshifted in Trigger ("SUM"); compare case-insensitively so
    # the assertion pins the value, not the casing.
    assert str(trigger.get("Statistic", "")).upper() == "SUM", (
        f"Trigger.Statistic={trigger.get('Statistic')!r}, expected SUM"
    )
    assert trigger["ComparisonOperator"] == "GreaterThanOrEqualToThreshold", trigger
    assert float(trigger["Threshold"]) == 1.0, trigger
    assert int(trigger["Period"]) == 60, trigger
    assert int(trigger["EvaluationPeriods"]) == 1, trigger
    dims = _normalized_dimensions(trigger.get("Dimensions"))
    assert dims == [("ProbeId", dim_value)], (
        f"Trigger.Dimensions must carry the alarm's dimensions, got "
        f"{trigger.get('Dimensions')!r}"
    )

    # --- the second observable: the action invocation recorded in alarm history ---
    def _action_items():
        return cw.describe_alarm_history(
            AlarmName=alarm, HistoryItemType="Action", MaxRecords=20
        )["AlarmHistoryItems"]

    items = _poll_until(
        _action_items,
        lambda got: any(
            topic["arn"] in (i.get("HistorySummary", "") + i.get("HistoryData", ""))
            for i in got
        ),
        timeout_s=120,
        interval_s=5.0,
        description=f"an Action history item naming {topic['arn']}",
    )
    naming = [
        i
        for i in items
        if topic["arn"] in (i.get("HistorySummary", "") + i.get("HistoryData", ""))
    ]
    assert naming, (
        f"DescribeAlarmHistory(HistoryItemType='Action') must record the invoked target; items "
        f"were {[i.get('HistorySummary') for i in items]}"
    )
    assert all(i["AlarmName"] == alarm for i in naming), naming


def _normalized_dimensions(raw: Any) -> list[tuple[str, str]]:
    """Read Trigger.Dimensions as (name, value) pairs regardless of key casing.

    The alarm notification uses lowercase {"name","value"} keys while the CloudWatch API uses
    {"Name","Value"}; the contractual content is the pair, not the casing.
    """
    if not isinstance(raw, list):
        return []
    pairs: list[tuple[str, str]] = []
    for d in raw:
        if not isinstance(d, dict):
            continue
        lowered = {str(k).lower(): v for k, v in d.items()}
        pairs.append((str(lowered.get("name")), str(lowered.get("value"))))
    return sorted(pairs)


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
        f"Payloads seen: {[p.get('AlarmName') for p in seen]}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
