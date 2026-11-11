"""forged-aws-es-searchable-documents-datapoint-rejected-and-alarm-withholds-notification."""
from __future__ import annotations

import datetime
import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "forged-aws-es-searchable-documents-datapoint-rejected-and-alarm-withholds-notification"
GROUP = 'alerting'
SERVICES = ['cloudwatch', 'opensearch', 'sns', 'sqs']

class _Accepted(AssertionError):
    """The call that real AWS refuses was ACCEPTED -- never confusable with an error code."""


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises; an accepted call raises `_Accepted`."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise _Accepted(f"the call was accepted, expected a rejection: {result!r}")


def _sns_to_sqs(ctx, scenario: str) -> tuple:
    """A topic whose notifications land in a queue we own (SNS envelope kept). -> (arn, url)."""
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-xsvc-osforge-")[:80],
        Tags=[{"Key": "sim2real", "Value": scenario}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-xsvc-osforge-")[:80],
        tags={"sim2real": scenario})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }]})})
    subscription = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn,
        ReturnSubscriptionArn=True)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=subscription))
    return topic_arn, queue_url


def _alarm(cw, name: str) -> dict:
    alarms = cw.describe_alarms(AlarmNames=[name], AlarmTypes=["MetricAlarm"])["MetricAlarms"]
    assert len(alarms) == 1, f"DescribeAlarms for {name!r} returned {len(alarms)!r} alarms: {alarms!r}"
    return alarms[0]


def _state_updates(cw, name: str) -> list:
    items: list = []
    for page in cw.get_paginator("describe_alarm_history").paginate(
            AlarmName=name, HistoryItemType="StateUpdate"):
        items.extend(page.get("AlarmHistoryItems", []))
    return items


def _drain_notifications(ctx, queue_url: str, deadline_s: float, *, until_alarm: str | None):
    """Receive and delete for up to deadline_s; return every CloudWatch notification seen.

    With until_alarm set, returns as soon as that alarm's notification has arrived.
    """
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + deadline_s
    seen: list = []
    while time.monotonic() < deadline:
        wait_s = int(max(0.0, min(10.0, deadline - time.monotonic())))
        received = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s)
        for message in received.get("Messages") or []:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])
            body = json.loads(message["Body"])
            if body.get("Type") == "Notification":
                seen.append(json.loads(body["Message"]))
        if until_alarm is not None and any(n.get("AlarmName") == until_alarm for n in seen):
            return seen
    return seen


_SCENARIO = "obs-opensearch-forged-aws-es-metric"
_POLL_S = 2.0
_ABSENCE_WINDOW_S = 10.0
_THRESHOLD = 10.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _put_alarm(ctx, cw, name, namespace, dims, topic_arn) -> None:
    cw.put_metric_alarm(
        AlarmName=name,
        AlarmDescription=f"sim2real {_SCENARIO}",
        Namespace=namespace,
        MetricName="SearchableDocuments",
        Dimensions=dims,
        Statistic="Maximum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=_THRESHOLD,
        ComparisonOperator="GreaterThanOrEqualToThreshold",
        AlarmActions=[topic_arn],
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))


# timing:real-time — metric: 47 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:rejection", "cap:c1", "cap:c4", "concern:e2e", "concern:eventing",
      "concern:metrics", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """PutMetricData into the reserved AWS/ES namespace is refused and stores nothing.

    An alarm on that series never notifies, while a twin alarm on a customer namespace does deliver.
    """
    cw = ctx.client("cloudwatch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    topic_arn, queue_url = _sns_to_sqs(ctx, _SCENARIO)

    # A domain name only this run can occupy, so every per-dimension read below is a property of
    # the query, not of what else lives in the account.
    domain = ctx.unique_name("sim2real-xsvc-osf-")[:28].rstrip("-")
    dims = [{"Name": "ClientId", "Value": account_id}, {"Name": "DomainName", "Value": domain}]
    control_ns = ctx.unique_name("sim2real/xsvc/osforge-")

    forged_alarm = ctx.unique_name("sim2real-xsvc-osforge-awses-")
    _put_alarm(ctx, cw, forged_alarm, "AWS/ES", dims, topic_arn)
    control_alarm = ctx.unique_name("sim2real-xsvc-osforge-ctrl-")
    _put_alarm(ctx, cw, control_alarm, control_ns, dims, topic_arn)

    datum = [{"MetricName": "SearchableDocuments", "Dimensions": dims, "Value": _THRESHOLD}]
    err = _error(lambda: cw.put_metric_data(Namespace="AWS/ES", MetricData=datum))
    expected = ("InvalidParameterValue", "The value AWS/ for parameter Namespace is invalid.")
    assert err == expected, (
        f"PutMetricData into the reserved AWS/ES namespace failed with {err!r}, expected "
        f"{expected!r}")

    # Positive control: the identical datapoint in a customer namespace is accepted and drives
    # its alarm into ALARM. Re-put each poll so a datapoint is always inside the evaluated period.
    started = time.monotonic()
    wait_s = _budget_s(ctx, 600.0)
    deadline = started + wait_s
    state = None
    while time.monotonic() < deadline:
        cw.put_metric_data(Namespace=control_ns, MetricData=datum)
        state = _alarm(cw, control_alarm)["StateValue"]
        if state == "ALARM":
            break
        time.sleep(_POLL_S)
    if state != "ALARM":
        if _budget_spent(ctx):
            raise TimeoutError(f"control alarm on {control_ns!r} reaching ALARM: the run budget ended "
                               "first; not graded")
        raise AssertionError(
            f"control alarm on {control_ns!r} did not reach ALARM within {wait_s:.0f}s "
            f"(state {state!r})")

    # Barrier: the control's notification must arrive through the shared topic and queue.
    seen = _drain_notifications(
        ctx, queue_url, _budget_s(ctx, 300.0), until_alarm=control_alarm)
    control_msgs = [n for n in seen if n.get("AlarmName") == control_alarm]
    if not control_msgs and _budget_spent(ctx):
        raise TimeoutError(f"the control alarm {control_alarm}'s notification: the run budget ended "
                           "first; not graded")
    assert len(control_msgs) == 1, (
        f"expected exactly one notification for the control alarm, got {len(control_msgs)!r}; "
        f"all notifications seen: {seen!r}")
    assert control_msgs[0]["NewStateValue"] == "ALARM", (
        f"the control notification's NewStateValue is {control_msgs[0]['NewStateValue']!r}")

    # Absence window: a fixed span read after the control's notification arrived.
    window = _ABSENCE_WINDOW_S
    seen += _drain_notifications(ctx, queue_url, window, until_alarm=None)
    forged_msgs = [n for n in seen if n.get("AlarmName") == forged_alarm]
    assert forged_msgs == [], (
        f"the alarm on the AWS/ES series notified although its only datapoint was refused: "
        f"{forged_msgs!r}")

    forged_state = _alarm(cw, forged_alarm)
    assert forged_state["StateValue"] == "INSUFFICIENT_DATA", (
        f"the alarm on the refused AWS/ES series is {forged_state['StateValue']!r} "
        f"({forged_state.get('StateReason')!r}), expected 'INSUFFICIENT_DATA'")
    into_alarm = [i for i in _state_updates(cw, forged_alarm)
                  if json.loads(i["HistoryData"]).get("newState", {}).get("stateValue") == "ALARM"]
    assert into_alarm == [], f"the AWS/ES alarm's history records an ALARM transition: {into_alarm!r}"

    now = datetime.datetime.now(datetime.timezone.utc)
    stats = cw.get_metric_statistics(
        Namespace="AWS/ES", MetricName="SearchableDocuments", Dimensions=dims,
        StartTime=now - datetime.timedelta(minutes=30), EndTime=now + datetime.timedelta(minutes=1),
        Period=60, Statistics=["Maximum"])
    assert stats["Datapoints"] == [], (
        f"the refused datapoint is readable under AWS/ES for {domain!r}: {stats['Datapoints']!r}")
    control_stats = cw.get_metric_statistics(
        Namespace=control_ns, MetricName="SearchableDocuments", Dimensions=dims,
        StartTime=now - datetime.timedelta(minutes=30), EndTime=now + datetime.timedelta(minutes=1),
        Period=60, Statistics=["Maximum"])
    assert control_stats["Datapoints"], (
        f"the accepted control datapoint is not readable under {control_ns!r}: {control_stats!r}")
    assert max(d["Maximum"] for d in control_stats["Datapoints"]) == _THRESHOLD, (
        f"the control series' Maximum is not {_THRESHOLD!r}: {control_stats['Datapoints']!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
