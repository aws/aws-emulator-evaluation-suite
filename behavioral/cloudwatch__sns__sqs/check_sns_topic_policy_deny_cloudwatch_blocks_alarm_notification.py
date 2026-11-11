"""sns-topic-policy-deny-cloudwatch-blocks-alarm-notification."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "sns-topic-policy-deny-cloudwatch-blocks-alarm-notification"

GROUP = "alerting"

SERVICES = ["cloudwatch", "sns", "sqs"]


@tags(
    "axis:negative-delivery",
    "cap:c4",
    "cap:c7",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "concern:metrics",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A topic policy denying cloudwatch.amazonaws.com Publish lets the alarm enter ALARM but
    delivers no notification, while the check's own publish to the topic arrives; dropping the Deny
    delivers the next ALARM notification."""
    topic, queue = _topic_to_queue(ctx)
    # Account id comes off the topic ARN so the check stays inside its declared SERVICES set.
    account = topic["arn"].split(":")[4]
    assert account, f"could not read the account id out of topic ARN {topic['arn']!r}"
    sns = ctx.client("sns")
    cw = ctx.client("cloudwatch")

    # (2) Owner Allow + explicit Deny for the CloudWatch service principal.
    sns.set_topic_attributes(
        TopicArn=topic["arn"],
        AttributeName="Policy",
        AttributeValue=json.dumps(_topic_policy(topic["arn"], account, deny_cw=True)),
    )

    alarm = _put_alarm(ctx, topic["arn"])
    cw.set_alarm_state(
        AlarmName=alarm, StateValue="ALARM", StateReason="probe: -> ALARM under deny"
    )

    # (3) The denial must not stop the alarm state machine.
    state = _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[alarm])["MetricAlarms"][0]["StateValue"],
        lambda s: s == "ALARM",
        timeout_s=60,
        interval_s=2.0,
        description=f"{alarm} transitions to ALARM despite the topic-policy deny",
    )
    assert state == "ALARM", (
        f"a topic-policy deny must not block the alarm state machine; {alarm} is {state!r}"
    )

    # (4) Control publish from the (still-allowed) account owner bounds the observation window.
    marker = ctx.unique_name("deny-probe-")
    sns.publish(TopicArn=topic["arn"], Message=json.dumps({"probe": marker}))
    _, seen = _await_message(
        ctx,
        queue["url"],
        lambda p: p.get("probe") == marker,
        timeout_s=180,
        description="owner control publish on the denied topic",
    )
    leaked = [p for p in seen if p.get("AlarmName") == alarm]
    assert not leaked, (
        f"an explicit topic-policy Deny on cloudwatch.amazonaws.com:Publish must suppress the "
        f"alarm notification, but {len(leaked)} notification(s) for {alarm} were delivered"
    )

    # (5) Control case: remove the Deny and the SAME alarm's action now delivers.
    sns.set_topic_attributes(
        TopicArn=topic["arn"],
        AttributeName="Policy",
        AttributeValue=json.dumps(_topic_policy(topic["arn"], account, deny_cw=False)),
    )
    cw.set_alarm_state(AlarmName=alarm, StateValue="OK", StateReason="probe: reset")
    cw.set_alarm_state(
        AlarmName=alarm, StateValue="ALARM", StateReason="probe: -> ALARM, deny removed"
    )
    matched, _ = _await_message(
        ctx,
        queue["url"],
        lambda p: p.get("AlarmName") == alarm,
        timeout_s=240,
        description=f"alarm notification for {alarm} once the Deny is removed",
    )
    assert matched["NewStateValue"] == "ALARM", (
        f"expected NewStateValue=ALARM after removing the Deny, got "
        f"{matched.get('NewStateValue')!r}"
    )


def _topic_policy(topic_arn: str, account: str, *, deny_cw: bool) -> dict[str, Any]:
    """The SNS access policy under test: owner Allow, plus (optionally) a CloudWatch Deny."""
    statements: list[dict[str, Any]] = [
        {
            "Sid": "AllowOwner",
            "Effect": "Allow",
            "Principal": {"AWS": account},
            "Action": "SNS:Publish",
            "Resource": topic_arn,
        },
        {
            "Sid": "AllowCloudWatchAlarms",
            "Effect": "Allow",
            "Principal": {"Service": "cloudwatch.amazonaws.com"},
            "Action": "SNS:Publish",
            "Resource": topic_arn,
        },
    ]
    if deny_cw:
        statements.append(
            {
                "Sid": "DenyCloudWatchAlarms",
                "Effect": "Deny",
                "Principal": {"Service": "cloudwatch.amazonaws.com"},
                "Action": "SNS:Publish",
                "Resource": topic_arn,
            }
        )
    return {"Version": "2012-10-17", "Statement": statements}


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
    """Create a metric alarm whose AlarmActions publish to the topic; returns the alarm name."""
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


def _inner_message(raw: str) -> dict[str, Any] | None:
    """Unwrap an SNS (non-raw) envelope and return its ["Message"] parsed as a dict.

    Returns None when the body is not an SNS Notification envelope; returns {"_raw": <str>} when
    the inner Message is not JSON. CloudWatch alarm notifications parse to a dict carrying
    AlarmName/NewStateValue/Trigger.
    """
    try:
        envelope = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(envelope, dict) or envelope.get("Type") != "Notification":
        return None
    body = envelope.get("Message")
    if not isinstance(body, str):
        return None
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return {"_raw": body}
    return parsed if isinstance(parsed, dict) else {"_raw": body}


def _await_message(
    ctx, queue_url: str, predicate, *, timeout_s=180.0, description="SNS message"
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Poll SQS until an unwrapped SNS message satisfying predicate arrives.

    Returns (matched, all_seen_in_order). The full list is the negative-delivery evidence.
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
            payload = _inner_message(msg.get("Body", ""))
            if payload is None:
                continue
            seen.append(payload)
            if predicate(payload):
                return payload, seen
    raise AssertionError(
        f"{description} not delivered within {timeout_s}s. Messages seen: {seen!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
