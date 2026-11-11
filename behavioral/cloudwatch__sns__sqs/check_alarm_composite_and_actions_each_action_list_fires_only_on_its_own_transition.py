"""alarm-composite-and-actions-each-action-list-fires-only-on-its-own-transition."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "alarm-composite-and-actions-each-action-list-fires-only-on-its-own-transition"
GROUP = "alerting"
SERVICES = ["cloudwatch", "sns", "sqs"]

_THRESHOLD = 50.0
_BREACH = 173.0
_CLEAR = 4.0
_STEP_BUDGET_S = 420.0
_CHECK_BUDGET_S = 1200.0


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
    """Driven by datapoints and by their absence, one alarm's OK, ALARM and INSUFFICIENT_DATA
    transitions each publish only to their own action list's topic, and every notification carries
    the documented body and Trigger block matching the alarm and the transition."""
    cw = ctx.client("cloudwatch")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    started = time.monotonic()
    budget = lambda: max(5.0, min(_STEP_BUDGET_S, _CHECK_BUDGET_S - (time.monotonic() - started)))

    queue_url, queue_arn = _queue(ctx, sqs)
    topics = {state: _topic(ctx, sns, state) for state in ("OK", "ALARM", "INSUFFICIENT_DATA")}
    _allow_topics(sqs, queue_url, queue_arn, list(topics.values()))
    for arn in topics.values():
        sub = sns.subscribe(TopicArn=arn, Protocol="sqs", Endpoint=queue_arn, ReturnSubscriptionArn=True)
        ctx.on_cleanup(lambda s=sub["SubscriptionArn"]: sns.unsubscribe(SubscriptionArn=s))

    namespace = ctx.unique_name("sim2real/cwroute-")
    metric = "queue-depth"
    dims = [{"Name": "Run", "Value": ctx.unique_name("run-")}, {"Name": "Tier", "Value": "web"}]
    name = ctx.unique_name("sim2real-cwroute-")
    description = f"sim2real three-action routing for {CHECK}"
    cw.put_metric_alarm(
        AlarmName=name,
        AlarmDescription=description,
        Namespace=namespace,
        MetricName=metric,
        Dimensions=dims,
        Statistic="Maximum",
        Period=10,
        EvaluationPeriods=1,
        Threshold=_THRESHOLD,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="missing",
        OKActions=[topics["OK"]],
        AlarmActions=[topics["ALARM"]],
        InsufficientDataActions=[topics["INSUFFICIENT_DATA"]],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))
    alarm_arn = _alarm(cw, name)["AlarmArn"]
    assert alarm_arn.split(":")[3] == ctx.region, f"AlarmArn {alarm_arn!r} not in {ctx.region!r}"

    received: list[tuple[dict, dict]] = []
    steps = [
        ("INSUFFICIENT_DATA", "OK", _CLEAR),
        ("OK", "ALARM", _BREACH),
        ("ALARM", "INSUFFICIENT_DATA", None),
    ]
    delivered = []
    for old, new, value in steps:
        each = (lambda v=value: _put(cw, namespace, metric, dims, v)) if value is not None else None
        observed = _wait_for(
            f"the alarm to move {old} -> {new} from "
            + (f"real datapoints of {value}" if value is not None else "the ABSENCE of datapoints"),
            lambda: _alarm(cw, name),
            lambda al, n=new: al["StateValue"] == n,
            budget(),
            each=each,
            during=lambda: _drain(sqs, queue_url, received),
        )
        env, msg = _wait_for_message(
            sqs, queue_url, received,
            lambda m, o=old, n=new: m.get("AlarmName") == name and m.get("NewStateValue") == n
            and m.get("OldStateValue") == o,
            budget(), f"the {old}->{new} notification",
        )
        assert env["TopicArn"] == topics[new], (
            f"the {old}->{new} transition was published to {env['TopicArn']!r}; only the {new} "
            f"action list ({topics[new]!r}) may fire on it"
        )
        assert env["Subject"] == f'{new}: "{name}" in {msg["Region"]}', f"Subject {env['Subject']!r}"
        assert msg["NewStateReason"] == observed["StateReason"], (
            f"notification NewStateReason {msg['NewStateReason']!r} != StateReason {observed['StateReason']!r}"
        )
        if value is not None:
            assert f"[{value}" in msg["NewStateReason"], (
                f"the reason for {old}->{new} does not cite the datapoint {value}: {msg['NewStateReason']!r}"
            )
        assert _parse_ts(msg["StateChangeTime"]) == observed["StateTransitionedTimestamp"], (
            f"StateChangeTime {msg['StateChangeTime']!r} != StateTransitionedTimestamp "
            f"{observed['StateTransitionedTimestamp']!r}"
        )
        delivered.append((old, new, env, msg))

    regions = set()
    for old, new, env, msg in delivered:
        expected = {
            "AlarmName": name,
            "AlarmDescription": description,
            "AlarmArn": alarm_arn,
            "AWSAccountId": alarm_arn.split(":")[4],
            "NewStateValue": new,
            "OldStateValue": old,
            "OKActions": [topics["OK"]],
            "AlarmActions": [topics["ALARM"]],
            "InsufficientDataActions": [topics["INSUFFICIENT_DATA"]],
        }
        for field, want in expected.items():
            assert msg.get(field) == want, f"{old}->{new} notification {field!r} = {msg.get(field)!r}, expected {want!r}"
        assert isinstance(msg.get("Region"), str) and msg["Region"], f"Region {msg.get('Region')!r}"
        regions.add(msg["Region"])
        trig = msg["Trigger"]
        want_trigger = {
            "Namespace": namespace,
            "MetricName": metric,
            "Statistic": "MAXIMUM",
            "StatisticType": "Statistic",
            "Period": 10,
            "EvaluationPeriods": 1,
            "ComparisonOperator": "GreaterThanThreshold",
            "Threshold": _THRESHOLD,
            "TreatMissingData": "missing",
        }
        for field, want in want_trigger.items():
            assert trig.get(field) == want, f"{old}->{new} Trigger.{field} = {trig.get(field)!r}, expected {want!r}"
        got_dims = sorted((d["name"], d["value"]) for d in trig["Dimensions"])
        assert got_dims == sorted((d["Name"], d["Value"]) for d in dims), (
            f"{old}->{new} Trigger.Dimensions = {trig['Dimensions']!r}, expected {dims!r}"
        )
    assert len(regions) == 1, f"notifications of one alarm disagree on Region: {sorted(regions)!r}"

    # No action list fired on another's transition: every message for this alarm came from the
    # topic of the state it announces, and the set of transitions announced is exactly the three
    # caused (a set, not a count: SNS->SQS delivery is at-least-once).
    mine = [(e["TopicArn"], m["OldStateValue"], m["NewStateValue"]) for e, m in received if m.get("AlarmName") == name]
    for topic, old, new in mine:
        assert topic == topics[new], f"a {old}->{new} notification arrived via {topic!r}"
    assert {(o, n) for _, o, n in mine} == {(o, n) for o, n, _ in steps}, (
        f"expected notifications for exactly the transitions {[(o, n) for o, n, _ in steps]!r}, got {mine!r}"
    )


def _alarm(cw, name: str) -> dict:
    resp = cw.describe_alarms(AlarmNames=[name], AlarmTypes=["MetricAlarm"])
    found = resp["MetricAlarms"]
    assert len(found) == 1, f"describe_alarms({name!r}) returned {len(found)} alarms"
    return found[0]


def _put(cw, namespace: str, metric: str, dims: list, value: float) -> None:
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": metric, "Dimensions": dims, "Value": value, "StorageResolution": 1}],
    )


def _wait_for(what, fetch, pred, budget_s, each=None, during=None, interval_s=5.0):
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
        if during is not None:
            during()
        else:
            time.sleep(interval_s)


def _parse_ts(value: str):
    from datetime import datetime

    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f%z")


def _drain(sqs, queue_url: str, into: list) -> None:
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=3)
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


def _queue(ctx, sqs) -> tuple[str, str]:
    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-cwroute-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    return queue_url, queue_arn


def _topic(ctx, sns, state: str) -> str:
    arn = sns.create_topic(
        Name=ctx.unique_name(f"sim2real-cwroute-{state.lower().replace('_', '')}-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


def _allow_topics(sqs, queue_url: str, queue_arn: str, topic_arns: list) -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arns}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
