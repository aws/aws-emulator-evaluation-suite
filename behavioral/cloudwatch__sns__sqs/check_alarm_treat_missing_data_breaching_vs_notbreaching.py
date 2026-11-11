"""alarm-treat-missing-data-breaching-vs-notbreaching."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "alarm-treat-missing-data-breaching-vs-notbreaching"

GROUP = "alerting"

SERVICES = ["cloudwatch", "sns", "sqs"]


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Two alarms differing ONLY in TreatMissingData diverge once data stops: `breaching` goes OK -> ALARM,
    names "treated as [Breaching]" in its StateReason and notifies, while `notBreaching` stays OK and
    delivers nothing on the same live topic."""
    topic, queue = _topic_to_queue(ctx)
    cw = ctx.client("cloudwatch")
    namespace = _xname(ctx, "ns")
    metric = "GapMetric"

    breaching = _put_gap_alarm(ctx, topic["arn"], namespace, metric, "breaching")
    not_breaching = _put_gap_alarm(ctx, topic["arn"], namespace, metric, "notBreaching")

    # Seed one NON-breaching datapoint so both alarms leave INSUFFICIENT_DATA with a known OK
    # baseline. Re-published each poll iteration so an evaluation cycle cannot miss it.
    def _seed_and_states() -> tuple[str, str]:
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[{"MetricName": metric, "Value": 1.0, "Unit": "Count"}],
        )
        return _states(cw, breaching, not_breaching)

    states = _poll_until(
        _seed_and_states,
        lambda s: s == ("OK", "OK"),
        timeout_s=240,
        interval_s=20.0,
        description="both alarms evaluate to OK from the seeded non-breaching datapoint",
    )
    assert states == ("OK", "OK"), f"baseline states were {states}, expected ('OK', 'OK')"

    # The delivery observation begins HERE, not at alarm creation. Both alarms were created with
    # ActionsEnabled=False and are switched on only now, with the queue emptied of anything the
    # setup produced, so every notification counted below was necessarily caused by data STOPPING.
    # Without this the breaching alarm's own startup INSUFFICIENT_DATA->ALARM transition -- which
    # real AWS does deliver, because 'no data yet' is exactly what this alarm treats as a breach --
    # sits in the queue and is indistinguishable from the transition under test.
    _drain(ctx, queue["url"])
    cw.enable_alarm_actions(AlarmNames=[breaching, not_breaching])
    enabled = {
        a["AlarmName"]: a["ActionsEnabled"]
        for a in cw.describe_alarms(AlarmNames=[breaching, not_breaching])["MetricAlarms"]
    }
    assert enabled == {breaching: True, not_breaching: True}, (
        f"both alarms must have actions enabled before the window under test, got {enabled}"
    )

    # Publishing STOPS here. The evaluation window slides onto missing data. On real AWS the
    # breaching-treated alarm flips ~400s after the last datapoint, so the deadline is 600s.
    diverged = _poll_until(
        lambda: _states(cw, breaching, not_breaching),
        lambda s: s[0] == "ALARM",
        timeout_s=600,
        interval_s=20.0,
        description=(
            f"TreatMissingData=breaching alarm {breaching} flips to ALARM on missing data"
        ),
    )
    assert diverged[0] == "ALARM", (
        f"TreatMissingData=breaching must treat the missing datapoint as a breach; "
        f"{breaching} is {diverged[0]!r}"
    )
    assert diverged[1] == "OK", (
        f"TreatMissingData=notBreaching must treat the SAME missing datapoint as within "
        f"threshold; {not_breaching} is {diverged[1]!r} (expected OK) -- the two alarms differ "
        f"only in TreatMissingData"
    )
    # The state alone could be reached by accident. The StateReason names the RULE the evaluation
    # engine applied, so this is the assertion an emulator that hardcodes a gap policy cannot fake.
    # Captured verbatim on real AWS: "Threshold Crossed: no datapoints were received for 1 period
    # and 1 missing datapoint was treated as [Breaching]".
    breach_reason = _state_reason(cw, breaching)
    assert "no datapoints were received for 1 period" in breach_reason, (
        f"the breach must be attributed to the MISSING period rather than to a datapoint, got "
        f"{breach_reason!r}"
    )
    assert "missing datapoint was treated as [Breaching]" in breach_reason, (
        f"the StateReason must name the TreatMissingData treatment that produced the state -- that "
        f"is what proves the engine applied this alarm's rule and not a fixed one -- got "
        f"{breach_reason!r}"
    )
    quiet_reason = _state_reason(cw, not_breaching)
    assert "[Breaching]" not in quiet_reason, (
        f"the notBreaching-treated alarm must never report a breaching fill: {quiet_reason!r}"
    )

    # Only the breaching alarm may notify. Its arrival bounds the window for a leaked one.
    payload, seen = _await_payload(
        ctx,
        queue["url"],
        lambda p: p.get("AlarmName") == breaching and p.get("NewStateValue") == "ALARM",
        timeout_s=240,
        description=f"notification for the missing-data breach of {breaching}",
    )
    assert payload["OldStateValue"] == "OK", (
        f"expected the OK->ALARM transition, got OldStateValue={payload.get('OldStateValue')!r}"
    )
    leaked = [p for p in seen if p.get("AlarmName") == not_breaching]
    assert not leaked, (
        f"the TreatMissingData=notBreaching alarm {not_breaching} must deliver nothing on "
        f"missing data, but {len(leaked)} notification(s) arrived: "
        f"{[p.get('NewStateValue') for p in leaked]}"
    )
    final = cw.describe_alarms(AlarmNames=[not_breaching])["MetricAlarms"][0]["StateValue"]
    assert final == "OK", (
        f"{not_breaching} must remain OK throughout the missing-data window, ended {final!r}"
    )


def _state_reason(cw, name: str) -> str:
    """The alarm's StateReason -- CloudWatch's own account of WHY it is in that state."""
    alarms = cw.describe_alarms(AlarmNames=[name], AlarmTypes=["MetricAlarm"])["MetricAlarms"]
    assert alarms, f"alarm {name} disappeared"
    return alarms[0].get("StateReason") or ""


def _states(cw, breaching: str, not_breaching: str) -> tuple[str, str]:
    """(state of the breaching-treated alarm, state of the notBreaching-treated alarm)."""
    by_name = {
        a["AlarmName"]: a["StateValue"]
        for a in cw.describe_alarms(AlarmNames=[breaching, not_breaching])["MetricAlarms"]
    }
    return by_name.get(breaching, "MISSING"), by_name.get(not_breaching, "MISSING")


def _put_gap_alarm(
    ctx, topic_arn: str, namespace: str, metric: str, treat_missing: str
) -> str:
    """An alarm over `namespace`/`metric` differing from its sibling ONLY in TreatMissingData.

    Created with ActionsEnabled=False and switched on only once the OK baseline is established.
    That is load-bearing, not tidiness: before any datapoint has EVER been published there is no
    data, which is precisely the condition TreatMissingData=breaching treats as a breach, so this
    alarm can enter ALARM from INSUFFICIENT_DATA at its very first evaluation -- measured on real
    AWS, where the delivered notification carried OldStateValue='INSUFFICIENT_DATA'. Leaving
    actions on from creation lets that STARTUP transition sit in the queue and be mistaken for the
    missing-data transition the check is actually about.
    """
    cw = ctx.client("cloudwatch")
    name = _xname(ctx, f"alarm-{treat_missing.lower()}")
    cw.put_metric_alarm(
        AlarmName=name,
        Namespace=namespace,
        MetricName=metric,
        Statistic="Maximum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=10.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData=treat_missing,
        ActionsEnabled=False,
        AlarmActions=[topic_arn],
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[name]))
    return name


def _drain(ctx, queue_url: str) -> int:
    """Empty the queue, returning how many messages were discarded.

    Called at the baseline so the delivery observation that follows can only contain transitions
    caused by data STOPPING, never anything from setting the alarms up.
    """
    sqs = ctx.client("sqs")
    discarded = 0
    while True:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2
        )
        messages = resp.get("Messages", [])
        if not messages:
            return discarded
        for msg in messages:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            discarded += 1


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
