"""alarm-composite-and-actions-disabled-actions-transition-but-delivery-blocked."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "alarm-composite-and-actions-disabled-actions-transition-but-delivery-blocked"
GROUP = "alerting"
SERVICES = ["cloudwatch", "sns", "sqs"]

_THRESHOLD = 50.0
_BREACH = 211.0
_CLEAR = 2.0
_STEP_BUDGET_S = 240.0
_CHECK_BUDGET_S = 900.0
_SILENCE_S = 45.0


# timing:real-time — metric: 10 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags(
    "axis:negative-delivery",
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
    """DisableAlarmActions blocks delivery while real evaluation still moves the alarm to ALARM.

    An enabled twin on the same metric and topic delivers; re-enabling restores delivery on the next
    transition.
    """
    cw = ctx.client("cloudwatch")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    started = time.monotonic()
    budget = lambda: max(5.0, min(_STEP_BUDGET_S, _CHECK_BUDGET_S - (time.monotonic() - started)))

    topic_arn, queue_url = _topic_to_queue(ctx, sns, sqs)
    namespace = ctx.unique_name("sim2real/cwmute-")
    metric = "latency"
    dims = [{"Name": "Run", "Value": ctx.unique_name("run-")}]

    names = {}
    for key in ("enabled", "muted"):
        name = ctx.unique_name(f"sim2real-cwmute-{key}-")
        cw.put_metric_alarm(
            AlarmName=name,
            AlarmDescription=f"sim2real {key} for {CHECK}",
            Namespace=namespace,
            MetricName=metric,
            Dimensions=dims,
            Statistic="Maximum",
            Period=10,
            EvaluationPeriods=1,
            Threshold=_THRESHOLD,
            ComparisonOperator="GreaterThanThreshold",
            TreatMissingData="ignore",
            AlarmActions=[topic_arn],
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        ctx.on_cleanup(lambda n=name: cw.delete_alarms(AlarmNames=[n]))
        names[key] = name
    enabled, muted = names["enabled"], names["muted"]

    cw.disable_alarm_actions(AlarmNames=[muted])
    assert _alarm(cw, muted)["ActionsEnabled"] is False, "DisableAlarmActions did not clear ActionsEnabled"
    assert _alarm(cw, enabled)["ActionsEnabled"] is True, "the control alarm lost ActionsEnabled"

    received: list[tuple[dict, dict]] = []
    both = _wait_for(
        "both alarms to reach ALARM from the same breaching datapoints",
        lambda: {n: _alarm(cw, n) for n in (enabled, muted)},
        lambda d: all(a["StateValue"] == "ALARM" for a in d.values()),
        budget(),
        each=lambda: _put(cw, namespace, metric, dims, _BREACH),
    )
    for n, al in both.items():
        assert f"[{_BREACH}" in al["StateReason"], (
            f"{n}'s StateReason does not cite the published datapoint {_BREACH}: {al['StateReason']!r}"
        )

    # Positive control: the enabled twin's notification arrives.
    env, msg = _wait_for_message(
        sqs, queue_url, received,
        lambda m: m.get("AlarmName") == enabled and m.get("NewStateValue") == "ALARM",
        budget(), "the enabled alarm's ALARM notification",
    )
    assert env["TopicArn"] == topic_arn, f"control notification came from {env['TopicArn']!r}"
    trig = msg["Trigger"]
    assert (trig["Namespace"], trig["MetricName"]) == (namespace, metric), (
        f"control notification Trigger names {trig['Namespace']!r}/{trig['MetricName']!r}"
    )
    assert msg["OldStateValue"] == "INSUFFICIENT_DATA", f"control OldStateValue {msg['OldStateValue']!r}"

    # Effect absent: the muted twin transitioned (history proves it) and delivered nothing.
    history = _history(cw, muted, "StateUpdate")
    to_alarm = [h for h in history if json.loads(h["HistoryData"])["newState"]["stateValue"] == "ALARM"]
    assert to_alarm, f"the muted alarm's history records no StateUpdate into ALARM: {history!r}"
    quiet_until = time.monotonic() + _SILENCE_S
    while time.monotonic() < quiet_until:
        _drain(sqs, queue_url, received)
    leaked = [m for _, m in received if m.get("AlarmName") == muted]
    assert leaked == [], f"the alarm with actions DISABLED still delivered: {leaked!r}"
    actions = _history(cw, muted, "Action")
    assert actions == [], f"the muted alarm recorded Action history items: {actions!r}"

    # Re-enable: the next real transition into ALARM is delivered.
    cw.enable_alarm_actions(AlarmNames=[muted])
    _wait_for(
        "the re-enabled alarm to return to OK from real datapoints",
        lambda: _alarm(cw, muted),
        lambda al: al["StateValue"] == "OK",
        budget(),
        each=lambda: _put(cw, namespace, metric, dims, _CLEAR),
    )
    _wait_for(
        "the re-enabled alarm to re-enter ALARM from real datapoints",
        lambda: _alarm(cw, muted),
        lambda al: al["StateValue"] == "ALARM",
        budget(),
        each=lambda: _put(cw, namespace, metric, dims, _BREACH),
    )
    _, restored = _wait_for_message(
        sqs, queue_url, received,
        lambda m: m.get("AlarmName") == muted and m.get("NewStateValue") == "ALARM",
        budget(), "the re-enabled alarm's ALARM notification",
    )
    assert restored["OldStateValue"] == "OK", (
        f"the first delivery after re-enabling must be the OK->ALARM transition, got "
        f"OldStateValue {restored['OldStateValue']!r}"
    )


def _alarm(cw, name: str) -> dict:
    resp = cw.describe_alarms(AlarmNames=[name], AlarmTypes=["CompositeAlarm", "MetricAlarm"])
    found = resp["MetricAlarms"] + resp["CompositeAlarms"]
    assert len(found) == 1, f"describe_alarms({name!r}) returned {len(found)} alarms"
    return found[0]


def _history(cw, name: str, item_type: str) -> list:
    items = []
    for page in cw.get_paginator("describe_alarm_history").paginate(
        AlarmName=name, HistoryItemType=item_type, AlarmTypes=["MetricAlarm"]
    ):
        items.extend(page["AlarmHistoryItems"])
    return items


def _put(cw, namespace: str, metric: str, dims: list, value: float) -> None:
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": metric, "Dimensions": dims, "Value": value, "StorageResolution": 1}],
    )


def _wait_for(what, fetch, pred, budget_s, each=None, interval_s=5.0):
    deadline = time.monotonic() + budget_s
    last = None
    while True:
        if each is not None:
            each()
        last = fetch()
        if pred(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {budget_s:.0f}s waiting for {what}; last={last!r}")
        time.sleep(interval_s)


def _drain(sqs, queue_url: str, into: list) -> None:
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
    for msg in resp.get("Messages", []):
        env = json.loads(msg["Body"])
        into.append((env, json.loads(env["Message"])))
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])


def _wait_for_message(sqs, queue_url, into, pred, budget_s, what):
    deadline = time.monotonic() + budget_s
    while True:
        for env, msg in into:
            if pred(msg):
                return env, msg
        if time.monotonic() >= deadline:
            seen = [(m.get("AlarmName"), m.get("OldStateValue"), m.get("NewStateValue")) for _, m in into]
            raise AssertionError(f"{what} was never delivered to SQS within {budget_s:.0f}s; saw {seen!r}")
        _drain(sqs, queue_url, into)


def _topic_to_queue(ctx, sns, sqs) -> tuple[str, str]:
    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-cwmute-"), Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-cwmute-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    sub = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn, ReturnSubscriptionArn=True)
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub["SubscriptionArn"]))
    return topic_arn, queue_url


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
