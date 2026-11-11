"""alarm-composite-and-actions-and-rule-waits-for-both-real-children."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "alarm-composite-and-actions-and-rule-waits-for-both-real-children"
GROUP = "alerting"
SERVICES = ["cloudwatch", "sns", "sqs"]

_THRESHOLD = 50.0
_BREACH = 137.0
_CLEAR = 3.0
_STEP_BUDGET_S = 240.0
_CHECK_BUDGET_S = 900.0
_HOLD_S = 30.0


# timing:real-time — metric: 10 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags(
    "axis:happy-path",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "concern:metrics",
    "concern:representation",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """Composite `ALARM(a) AND ALARM(b)` alarms only once real datapoints put both children in ALARM.

    StateReason and the delivered SNS -> SQS notification name the child that completed the rule;
    clearing a returns the composite to OK and notifies again.
    """
    cw = ctx.client("cloudwatch")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    started = time.monotonic()
    budget = lambda: max(5.0, min(_STEP_BUDGET_S, _CHECK_BUDGET_S - (time.monotonic() - started)))

    topic_arn, queue_url = _topic_to_queue(ctx, sns, sqs)
    namespace = ctx.unique_name("sim2real/cwcomp-")
    dim_value = ctx.unique_name("run-")
    dims = [{"Name": "Run", "Value": dim_value}]

    child = {}
    for key in ("a", "b"):
        name = ctx.unique_name(f"sim2real-cwcomp-and-{key}-")
        cw.put_metric_alarm(
            AlarmName=name,
            Namespace=namespace,
            MetricName=f"metric-{key}",
            Dimensions=dims,
            Statistic="Maximum",
            Period=10,
            EvaluationPeriods=1,
            Threshold=_THRESHOLD,
            ComparisonOperator="GreaterThanThreshold",
            TreatMissingData="ignore",
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        ctx.on_cleanup(lambda n=name: cw.delete_alarms(AlarmNames=[n]))
        child[key] = name

    composite = ctx.unique_name("sim2real-cwcomp-and-")
    rule = f'ALARM("{child["a"]}") AND ALARM("{child["b"]}")'
    description = f"sim2real composite AND for {CHECK}"
    cw.put_composite_alarm(
        AlarmName=composite,
        AlarmRule=rule,
        AlarmDescription=description,
        AlarmActions=[topic_arn],
        OKActions=[topic_arn],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    # LIFO: registered after the children, so the composite is deleted FIRST and the children's
    # deletes are not refused for being referenced.
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[composite]))

    arn = {k: _alarm(cw, n)["AlarmArn"] for k, n in child.items()}
    composite_arn = _alarm(cw, composite)["AlarmArn"]
    assert composite_arn.split(":")[3] == ctx.region, (
        f"composite AlarmArn {composite_arn!r} is not in region {ctx.region!r}"
    )
    received: list[tuple[dict, dict]] = []

    # Only a breaches: the composite must hold OK.
    first = _wait_for(
        "child a to reach ALARM from real datapoints",
        lambda: _alarm(cw, child["a"]),
        lambda al: al["StateValue"] == "ALARM",
        budget(),
        each=lambda: _put(cw, namespace, "metric-a", dims, _BREACH),
    )
    assert f"[{_BREACH}" in first["StateReason"], (
        f"child a's StateReason does not cite the published datapoint {_BREACH}: "
        f"{first['StateReason']!r}"
    )
    assert _alarm(cw, child["b"])["StateValue"] == "INSUFFICIENT_DATA", (
        f"child b has never received a datapoint yet reports {_alarm(cw, child['b'])['StateValue']!r}"
    )
    hold_until = time.monotonic() + _HOLD_S
    while time.monotonic() < hold_until:
        state = _alarm(cw, composite)["StateValue"]
        assert state == "OK", (
            f"with only child a in ALARM (b INSUFFICIENT_DATA) the AND composite reports {state!r}; "
            f"ALARM(a) AND ALARM(b) is false, so it must stay OK"
        )
        _drain(sqs, queue_url, received)
        time.sleep(5)
    early = [m for _, m in received if m.get("AlarmName") == composite and m.get("NewStateValue") == "ALARM"]
    assert early == [], f"the AND composite delivered an ALARM notification with one child: {early!r}"

    # b breaches too; the rule is now satisfied.
    _wait_for(
        "child b to reach ALARM from real datapoints",
        lambda: _alarm(cw, child["b"]),
        lambda al: al["StateValue"] == "ALARM",
        budget(),
        each=lambda: _put(cw, namespace, "metric-b", dims, _BREACH),
    )
    fired = _wait_for(
        "the AND composite to reach ALARM once both children are in ALARM",
        lambda: _alarm(cw, composite),
        lambda al: al["StateValue"] == "ALARM",
        budget(),
    )
    assert fired["StateReason"].startswith(f"{arn['b']} transitioned to ALARM"), (
        f"the composite's StateReason must name child b, the child whose transition completed the "
        f"rule; got {fired['StateReason']!r}"
    )
    reason_data = json.loads(fired["StateReasonData"])
    triggering = {t["arn"]: t["state"]["value"] for t in reason_data["triggeringAlarms"]}
    assert triggering == {arn["a"]: "ALARM", arn["b"]: "ALARM"}, (
        f"StateReasonData.triggeringAlarms must list both children in ALARM, got {triggering!r}"
    )

    env, alarm_msg = _wait_for_message(
        sqs, queue_url, received,
        lambda m: m.get("AlarmName") == composite and m.get("NewStateValue") == "ALARM",
        budget(), "the composite's ALARM notification",
    )
    assert env["TopicArn"] == topic_arn, f"notification came from {env['TopicArn']!r}, expected {topic_arn!r}"
    assert env["Type"] == "Notification", f"SNS envelope Type {env['Type']!r}"
    expected = {
        "AlarmName": composite,
        "AlarmDescription": description,
        "AlarmArn": composite_arn,
        "AWSAccountId": composite_arn.split(":")[4],
        "NewStateValue": "ALARM",
        "OldStateValue": "OK",
        "NewStateReason": fired["StateReason"],
        "AlarmRule": rule,
        "AlarmActions": [topic_arn],
        "OKActions": [topic_arn],
        "InsufficientDataActions": [],
    }
    for field, want in expected.items():
        assert alarm_msg.get(field) == want, (
            f"composite notification field {field!r} is {alarm_msg.get(field)!r}, expected {want!r}"
        )
    assert _parse_ts(alarm_msg["StateChangeTime"]) == fired["StateTransitionedTimestamp"], (
        f"notification StateChangeTime {alarm_msg['StateChangeTime']!r} is not the composite's "
        f"StateTransitionedTimestamp {fired['StateTransitionedTimestamp']!r}"
    )
    assert isinstance(alarm_msg.get("Region"), str) and alarm_msg["Region"], (
        f"notification Region is {alarm_msg.get('Region')!r}"
    )
    assert env["Subject"] == f'ALARM: "{composite}" in {alarm_msg["Region"]}', (
        f"SNS Subject {env['Subject']!r} does not match the documented 'ALARM: \"<name>\" in <Region>'"
    )
    children = {c["Arn"]: c["State"]["Value"] for c in alarm_msg["TriggeringChildren"]}
    assert children == {arn["a"]: "ALARM", arn["b"]: "ALARM"}, (
        f"TriggeringChildren must be both children in ALARM, got {children!r}"
    )
    assert "Trigger" not in alarm_msg, (
        f"a composite notification has no metric Trigger block, got {alarm_msg.get('Trigger')!r}"
    )

    # a clears; the conjunction is false again.
    _wait_for(
        "child a to return to OK from real datapoints",
        lambda: _alarm(cw, child["a"]),
        lambda al: al["StateValue"] == "OK",
        budget(),
        each=lambda: _put(cw, namespace, "metric-a", dims, _CLEAR),
    )
    cleared = _wait_for(
        "the AND composite to return to OK once child a leaves ALARM",
        lambda: _alarm(cw, composite),
        lambda al: al["StateValue"] == "OK",
        budget(),
    )
    assert cleared["StateReason"].startswith(f"{arn['a']} transitioned to OK"), (
        f"the composite's OK StateReason must name child a, got {cleared['StateReason']!r}"
    )
    _, ok_msg = _wait_for_message(
        sqs, queue_url, received,
        lambda m: m.get("AlarmName") == composite and m.get("NewStateValue") == "OK"
        and m.get("OldStateValue") == "ALARM",
        budget(), "the composite's ALARM->OK notification",
    )
    assert ok_msg["NewStateReason"] == cleared["StateReason"], (
        f"OK notification reason {ok_msg['NewStateReason']!r} != StateReason {cleared['StateReason']!r}"
    )
    # One transition into ALARM happened, so every ALARM notification (SNS->SQS is at-least-once,
    # so possibly repeated) must announce that same transition.
    alarm_times = {
        m["StateChangeTime"] for _, m in received
        if m.get("AlarmName") == composite and m.get("NewStateValue") == "ALARM"
    }
    assert alarm_times == {alarm_msg["StateChangeTime"]}, (
        f"the composite entered ALARM once but notifications announce transitions at {sorted(alarm_times)!r}"
    )


def _alarm(cw, name: str) -> dict:
    resp = cw.describe_alarms(AlarmNames=[name], AlarmTypes=["CompositeAlarm", "MetricAlarm"])
    found = resp["MetricAlarms"] + resp["CompositeAlarms"]
    assert len(found) == 1, f"describe_alarms({name!r}) returned {len(found)} alarms"
    return found[0]


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


def _parse_ts(value: str):
    from datetime import datetime

    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f%z")


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
        Name=ctx.unique_name("sim2real-cwcomp-"), Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-cwcomp-"), tags={"sim2real": CHECK}
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
