"""alarm-composite-and-actions-set-alarm-state-fires-action-then-evaluation-overwrites."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "alarm-composite-and-actions-set-alarm-state-fires-action-then-evaluation-overwrites"
GROUP = "alerting"
SERVICES = ["cloudwatch", "sns", "sqs"]

_THRESHOLD = 50.0
_CLEAR = 6.0
_FORCED_REASON = "sim2real: forced by SetAlarmState, no datapoint breached"
_STEP_BUDGET_S = 300.0
_CHECK_BUDGET_S = 900.0


# timing:real-time — metric: 10 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags(
    "axis:happy-path",
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
    """SetAlarmState(ALARM) delivers the ALARM notification with the forced reason but writes no
    datapoint, and the next evaluation of the below-threshold data moves the alarm back to OK with
    an evaluator-authored reason, delivering the OK notification."""
    cw = ctx.client("cloudwatch")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    started = time.monotonic()
    budget = lambda: max(5.0, min(_STEP_BUDGET_S, _CHECK_BUDGET_S - (time.monotonic() - started)))
    t_start = datetime.now(timezone.utc) - timedelta(minutes=2)

    topic_arn, queue_url = _topic_to_queue(ctx, sns, sqs)
    namespace = ctx.unique_name("sim2real/cwforce-")
    metric = "errors"
    dims = [{"Name": "Run", "Value": ctx.unique_name("run-")}]
    name = ctx.unique_name("sim2real-cwforce-")
    cw.put_metric_alarm(
        AlarmName=name,
        AlarmDescription=f"sim2real forced-state for {CHECK}",
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
        OKActions=[topic_arn],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))
    feed = lambda: _put(cw, namespace, metric, dims, _CLEAR)
    received: list[tuple[dict, dict]] = []

    ok = _wait_for(
        "the alarm to reach OK from real below-threshold datapoints",
        lambda: _alarm(cw, name), lambda al: al["StateValue"] == "OK", budget(), each=feed,
    )
    assert _FORCED_REASON not in ok["StateReason"], f"unexpected reason {ok['StateReason']!r}"
    # The OK notification of step 1 is the positive control that the delivery path is live.
    _wait_for_message(
        sqs, queue_url, received,
        lambda m: m.get("AlarmName") == name and m.get("NewStateValue") == "OK"
        and m.get("OldStateValue") == "INSUFFICIENT_DATA",
        budget(), "the evaluator's INSUFFICIENT_DATA->OK notification",
    )

    cw.set_alarm_state(AlarmName=name, StateValue="ALARM", StateReason=_FORCED_REASON)
    _, forced = _wait_for_message(
        sqs, queue_url, received,
        lambda m: m.get("AlarmName") == name and m.get("NewStateValue") == "ALARM",
        budget(), "the ALARM notification fired by SetAlarmState",
    )
    assert forced["NewStateReason"] == _FORCED_REASON, (
        f"the forced notification's NewStateReason is {forced['NewStateReason']!r}, expected the "
        f"SetAlarmState reason {_FORCED_REASON!r}"
    )
    assert forced["OldStateValue"] == "OK", f"forced notification OldStateValue {forced['OldStateValue']!r}"

    reclaimed = _wait_for(
        "real evaluation to overwrite the forced ALARM back to OK",
        lambda: _alarm(cw, name),
        lambda al: al["StateValue"] == "OK" and al["StateReason"] != ok["StateReason"],
        budget(),
        each=feed,
    )
    assert reclaimed["StateReason"].startswith("Threshold Crossed"), (
        f"the reclaiming reason should be evaluator-authored, got {reclaimed['StateReason']!r}"
    )
    assert f"[{_CLEAR}" in reclaimed["StateReason"], (
        f"the reclaiming reason does not cite the published datapoint {_CLEAR}: {reclaimed['StateReason']!r}"
    )
    _, back = _wait_for_message(
        sqs, queue_url, received,
        lambda m: m.get("AlarmName") == name and m.get("NewStateValue") == "OK"
        and m.get("OldStateValue") == "ALARM",
        budget(), "the evaluator's ALARM->OK notification after the force",
    )
    assert back["NewStateReason"] == reclaimed["StateReason"], (
        f"OK notification reason {back['NewStateReason']!r} != StateReason {reclaimed['StateReason']!r}"
    )

    # The force wrote nothing into the metric: every datapoint over the run is below threshold.
    stats = cw.get_metric_statistics(
        Namespace=namespace, MetricName=metric, Dimensions=dims,
        StartTime=t_start, EndTime=datetime.now(timezone.utc) + timedelta(minutes=1),
        Period=10, Statistics=["Maximum"],
    )["Datapoints"]
    assert stats, "GetMetricStatistics returned no datapoints for a metric this check published to"
    peak = max(d["Maximum"] for d in stats)
    assert peak == _CLEAR, (
        f"the metric's Maximum over the run is {peak!r}; only {_CLEAR} was published, so SetAlarmState "
        f"must not have written any datapoint"
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
        Name=ctx.unique_name("sim2real-cwforce-"), Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-cwforce-"), tags={"sim2real": CHECK}
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
