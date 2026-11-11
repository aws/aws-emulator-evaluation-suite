"""metric-datapoints-cross-threshold-and-notify."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metric-datapoints-cross-threshold-and-notify"

GROUP = "alerting"

SERVICES = ["cloudwatch", "sns", "sqs"]


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags(
    "axis:happy-path",
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
    """Published datapoints move an alarm to OK and then to ALARM by evaluation, StateReasonData
    records threshold 10, period 60 and statistic Maximum, and the notification reports OK -> ALARM
    with the alarm's namespace and metric."""
    deadline = time.monotonic() + _CLASS_BUDGET_S - _TEARDOWN_RESERVE_S
    topic, queue, sub_arn = _topic_to_queue(ctx)
    cw = ctx.client("cloudwatch")

    namespace = _xname(ctx, "ns")
    metric = "ThresholdMetric"
    alarm = _xname(ctx, "alarm")
    cw.put_metric_alarm(
        AlarmName=alarm,
        Namespace=namespace,
        MetricName=metric,
        Statistic="Maximum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=10.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
        ActionsEnabled=True,
        AlarmActions=[topic["arn"]],
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(
        _tolerant(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[alarm]), "ResourceNotFound")
    )

    def _publish(value: float) -> str:
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[{"MetricName": metric, "Value": value, "Unit": "Count"}],
        )
        return cw.describe_alarms(AlarmNames=[alarm])["MetricAlarms"][0]["StateValue"]

    # (1) Non-breaching data must evaluate to OK, not ALARM (an engine that alarms on any
    # datapoint, or never evaluates at all, fails here).
    state = _poll_until(
        lambda: _publish(1.0),
        lambda s: s == "OK",
        timeout_s=_left(deadline),
        interval_s=20.0,
        description=f"{alarm} evaluates to OK from a non-breaching datapoint (1.0 <= 10.0)",
    )
    assert state == "OK", f"expected OK from non-breaching data, got {state!r}"

    # (2) Breaching data must flip the engine's own evaluation to ALARM.
    state = _poll_until(
        lambda: _publish(100.0),
        lambda s: s == "ALARM",
        timeout_s=_left(deadline),
        interval_s=20.0,
        description=f"{alarm} evaluates to ALARM from breaching datapoints (100.0 > 10.0)",
    )
    assert state == "ALARM", f"expected ALARM from breaching data, got {state!r}"

    described = cw.describe_alarms(AlarmNames=[alarm])["MetricAlarms"][0]
    assert described.get("StateReasonData"), (
        f"an engine-evaluated ALARM must carry StateReasonData, got keys {sorted(described)}"
    )
    reason_data = json.loads(described["StateReasonData"])
    assert float(reason_data.get("threshold", "nan")) == 10.0, (
        f"StateReasonData must record the threshold the engine evaluated, got {reason_data!r}"
    )
    assert int(reason_data.get("period", -1)) == 60, (
        f"StateReasonData must record the evaluation period, got {reason_data!r}"
    )
    assert str(reason_data.get("statistic", "")).lower() == "maximum", (
        f"StateReasonData must record the evaluated statistic, got {reason_data!r}"
    )

    # (3) The ENGINE-derived transition must fire the action.
    payload, _ = _await_payload(
        ctx,
        queue["url"],
        lambda p: p.get("AlarmName") == alarm and p.get("NewStateValue") == "ALARM",
        timeout_s=_left(deadline),
        description=f"notification for the engine-derived ALARM transition of {alarm}",
    )
    assert payload["OldStateValue"] == "OK", (
        f"the delivered transition must be the engine's OK->ALARM one (proving it came from the "
        f"evaluated datapoints, not a cold INSUFFICIENT_DATA start), got OldStateValue="
        f"{payload.get('OldStateValue')!r}"
    )
    trigger = payload.get("Trigger", {})
    assert trigger.get("Namespace") == namespace, trigger
    assert trigger.get("MetricName") == metric, trigger

    # Tear down in reverse dependency order and prove each resource gone.
    _gone_alarm(ctx, alarm)
    _gone_subscription(ctx, sub_arn, topic["arn"])
    _gone_topic(ctx, topic["arn"])
    _gone_queue(ctx, queue["name"], queue["url"])


#: The default service-class budget (CloudWatch is not a long class) and the share of it the
#: in-body teardown keeps; the evaluation phases poll within the rest.
_CLASS_BUDGET_S = 300.0
_TEARDOWN_RESERVE_S = 60.0


def _left(deadline: float) -> float:
    """Seconds left before the shared phase deadline (at least one poll)."""
    return max(1.0, deadline - time.monotonic())


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
    ctx.on_cleanup(_tolerant(lambda: sqs.delete_queue(QueueUrl=url), *_SQS_NF))
    return {"name": name, "url": url, "arn": arn}


def _create_topic(ctx) -> dict[str, str]:
    """Create an SNS topic (registers delete_topic teardown). Returns {name,arn}."""
    name = _xname(ctx, "topic")
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=name, Tags=_xsvc_tags_kv())["TopicArn"]
    ctx.on_cleanup(_tolerant(lambda: sns.delete_topic(TopicArn=arn), "NotFound"))
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
        _tolerant(
            lambda: ctx.client("sns").unsubscribe(SubscriptionArn=sub["SubscriptionArn"]),
            "NotFound",
        )
    )
    return topic, queue, sub["SubscriptionArn"]


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


#: Bounded convergence for a delete to reach its terminal not-found answer (the default service
#: class budget); a deadline, never an assertion on elapsed time.
_GONE_S = 120.0


def _err(exc: ClientError) -> tuple[str, int, str]:
    """(code, HTTP status, message) of a ClientError."""
    e = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return e.get("Code") or "", status, e.get("Message") or e.get("message") or ""


def _refused(fn, codes: tuple[str, ...], status: int, what: str, message: str) -> None:
    """``fn()`` must fail with one of ``codes`` at ``status`` and exactly ``message``.

    AWS sends some errors with an empty message (CloudWatch ResourceNotFound): ``message`` is "".
    """
    try:
        fn()
    except ClientError as exc:
        code, got, msg = _err(exc)
        assert code in codes and got == status, (
            f"{what}: expected {'/'.join(codes)} HTTP {status}, got {code!r} HTTP {got!r}: {msg[:150]!r}"
        )
        assert msg == message, f"{what}: {code} message is {msg!r}, expected {message!r}"
        return
    raise AssertionError(f"{what}: expected {'/'.join(codes)} HTTP {status}, the call succeeded")


def _poll_refused(fn, codes, status, what, message, timeout_s: float = _GONE_S) -> None:
    """Poll ``fn`` until it reaches the terminal not-found answer, then grade it with ``_refused``.

    A success while the delete converges is retried; any other error fails at once.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            code, _, _ = _err(exc)
            if code in codes:
                _refused(fn, codes, status, what, message)
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: still readable {timeout_s:.0f}s after the delete")
        time.sleep(1.0)


def _tolerant(fn, *codes: str):
    """A teardown that ignores only the given not-found codes (the body already deleted it)."""

    def run() -> None:
        try:
            fn()
        except ClientError as exc:
            if _err(exc)[0] not in codes:
                raise

    return run


def _paged(client, op: str, key: str, **kw) -> list:
    """Every element of ``key`` across all pages of ``op``."""
    out: list = []
    for page in client.get_paginator(op).paginate(**kw):
        out.extend(page.get(key, []))
    return out


_SQS_NF = ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist")
_SQS_NF_MSG = "The specified queue does not exist."


def _gone_alarm(ctx, name: str) -> None:
    cw = ctx.client("cloudwatch")
    cw.delete_alarms(AlarmNames=[name])
    # AWS has no not-found code for DescribeAlarms: the in-band miss is beat 1.
    by_name = cw.describe_alarms(AlarmNames=[name])
    assert not by_name.get("MetricAlarms") and not by_name.get("CompositeAlarms"), f"DescribeAlarms still returns deleted alarm {name}"
    listed = {a["AlarmName"] for a in cw.describe_alarms(AlarmNamePrefix=name).get("MetricAlarms", [])}
    assert name not in listed, f"DescribeAlarms(prefix) still lists deleted alarm {name}"
    _refused(lambda: cw.set_alarm_state(AlarmName=name, StateValue="OK", StateReason="gone"),
             ("ResourceNotFound",), 404, f"SetAlarmState {name}", "")


def _gone_subscription(ctx, sub_arn: str, topic_arn: str) -> None:
    sns = ctx.client("sns")
    sns.unsubscribe(SubscriptionArn=sub_arn)
    nf = ("NotFound",)
    _poll_refused(lambda: sns.get_subscription_attributes(SubscriptionArn=sub_arn), nf, 404, "GetSubscriptionAttributes",
                  "Subscription does not exist")
    listed = {s["SubscriptionArn"] for s in _paged(sns, "list_subscriptions_by_topic", "Subscriptions", TopicArn=topic_arn)}
    assert sub_arn not in listed, "ListSubscriptionsByTopic still lists the removed subscription"
    _refused(
        lambda: sns.set_subscription_attributes(SubscriptionArn=sub_arn, AttributeName="RawMessageDelivery", AttributeValue="true"),
        nf, 404, "SetSubscriptionAttributes on removed subscription", "Subscription does not exist",
    )


def _gone_topic(ctx, arn: str) -> None:
    sns = ctx.client("sns")
    sns.delete_topic(TopicArn=arn)
    nf = ("NotFound",)
    _poll_refused(lambda: sns.get_topic_attributes(TopicArn=arn), nf, 404, "GetTopicAttributes", "Topic does not exist")
    listed = {t["TopicArn"] for t in _paged(sns, "list_topics", "Topics")}
    assert arn not in listed, "ListTopics still lists the deleted topic"
    _refused(lambda: sns.publish(TopicArn=arn, Message="gone"), nf, 404, "Publish to deleted topic",
             "Topic does not exist")


def _gone_queue(ctx, name: str, url: str) -> None:
    sqs = ctx.client("sqs")
    sqs.delete_queue(QueueUrl=url)
    # AWS documents up to 60 s for a deleted queue to stop answering.
    _poll_refused(lambda: sqs.get_queue_url(QueueName=name), _SQS_NF, 400, f"GetQueueUrl {name}", _SQS_NF_MSG)
    listed = sqs.list_queues(QueueNamePrefix=name).get("QueueUrls", [])
    assert not [u for u in listed if u.rstrip("/").split("/")[-1] == name], (
        f"ListQueues still lists deleted queue {name}"
    )
    _refused(lambda: sqs.send_message(QueueUrl=url, MessageBody="gone"), _SQS_NF, 400, f"SendMessage {name}",
             _SQS_NF_MSG)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
