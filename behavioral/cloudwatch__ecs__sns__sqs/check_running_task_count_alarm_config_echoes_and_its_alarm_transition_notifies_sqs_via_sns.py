"""running-task-count-alarm-config-echoes-and-its-alarm-transition-notifies-sqs-via-sns."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "running-task-count-alarm-config-echoes-and-its-alarm-transition-notifies-sqs-via-sns"
GROUP = "alarm-notification"
SERVICES = ["cloudwatch", "ecs", "sns", "sqs"]

_NS = "ECS/ContainerInsights"
_METRIC = "RunningTaskCount"
_PERIOD_S = 60
_EVALUATION_PERIODS = 2


@tags(
    "axis:happy-path",
    "concern:metrics",
    "concern:eventing",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """A RunningTaskCount < 1 alarm on a Container Insights cluster echoes its 60 s x 2 breaching
    configuration; its OK -> ALARM transition is in history and its SNS action delivers a message
    to SQS whose Trigger names the metric, its dimensions and that configuration.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
    """
    ecs = ctx.client("ecs")
    cw = ctx.client("cloudwatch")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    cluster = ctx.unique_name("sim2real-xsvc-rtc-")
    ecs.create_cluster(clusterName=cluster,
                       settings=[{"name": "containerInsights", "value": "enabled"}],
                       tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_cluster(ecs, cluster))
    described = ecs.describe_clusters(clusters=[cluster], include=["SETTINGS"])["clusters"]
    assert len(described) == 1, f"DescribeClusters returned {described!r}"
    settings = {s["name"]: s["value"] for s in described[0].get("settings", [])}
    assert settings.get("containerInsights") == "enabled", (
        f"cluster {cluster} reports settings {settings!r}; containerInsights was set to enabled")
    service = ctx.unique_name("sim2real-xsvc-rtc-svc-")

    queue_name = ctx.unique_name("sim2real-xsvc-rtc-q-")
    queue_url = sqs.create_queue(QueueName=queue_name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"]["QueueArn"]
    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-xsvc-rtc-t-"),
                                 Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
                       "Action": "sqs:SendMessage", "Resource": queue_arn,
                       "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}}}]})})
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn,
                            ReturnSubscriptionArn=True)["SubscriptionArn"]
    ctx.on_cleanup(lambda: _unsubscribe(sns, sub_arn))

    alarm = ctx.unique_name("sim2real-xsvc-rtc-alarm-")
    dims = [{"Name": "ClusterName", "Value": cluster}, {"Name": "ServiceName", "Value": service}]
    cw.put_metric_alarm(
        AlarmName=alarm, AlarmDescription=f"sim2real {CHECK}", Namespace=_NS,
        MetricName=_METRIC, Statistic="Maximum", Period=_PERIOD_S,
        EvaluationPeriods=_EVALUATION_PERIODS, DatapointsToAlarm=_EVALUATION_PERIODS, Threshold=1.0,
        ComparisonOperator="LessThanThreshold", TreatMissingData="breaching",
        Dimensions=dims, AlarmActions=[topic_arn], Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm]))

    stored = _alarm(cw, alarm)
    got = {k: stored.get(k) for k in ("Namespace", "MetricName", "Statistic", "Period",
                                      "EvaluationPeriods", "DatapointsToAlarm", "Threshold",
                                      "ComparisonOperator", "TreatMissingData", "AlarmActions")}
    want = {"Namespace": _NS, "MetricName": _METRIC, "Statistic": "Maximum", "Period": _PERIOD_S,
            "EvaluationPeriods": _EVALUATION_PERIODS, "DatapointsToAlarm": _EVALUATION_PERIODS,
            "Threshold": 1.0, "ComparisonOperator": "LessThanThreshold",
            "TreatMissingData": "breaching", "AlarmActions": [topic_arn]}
    assert got == want, f"alarm {alarm} reads {got!r}, it was created as {want!r}"
    stored_dims = {d["Name"]: d["Value"] for d in stored["Dimensions"]}
    assert stored_dims == {"ClusterName": cluster, "ServiceName": service}, (
        f"alarm {alarm} reports dimensions {stored_dims!r}")

    # The evaluator may itself move the alarm (missing data is breaching); every interleaving still
    # records an OK -> ALARM transition after the two forced states.
    cw.set_alarm_state(AlarmName=alarm, StateValue="OK", StateReason="sim2real: task running")
    cw.set_alarm_state(AlarmName=alarm, StateValue="ALARM",
                       StateReason="sim2real: running task count below 1")

    def _ok_to_alarm() -> list[dict]:
        out = []
        for page in cw.get_paginator("describe_alarm_history").paginate(
                AlarmName=alarm, HistoryItemType="StateUpdate", ScanBy="TimestampAscending"):
            for item in page["AlarmHistoryItems"]:
                data = json.loads(item["HistoryData"])
                if (data.get("oldState", {}).get("stateValue"),
                        data.get("newState", {}).get("stateValue")) == ("OK", "ALARM"):
                    out.append(data)
        return out

    _poll_until(ctx, _ok_to_alarm, lambda h: len(h) >= 1, timeout_s=120.0, interval_s=2.0,
                description=f"an OK -> ALARM transition of {alarm} in DescribeAlarmHistory")

    def _drain() -> list[dict]:
        msgs = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10,
                                   WaitTimeSeconds=10).get("Messages", [])
        out = []
        for m in msgs:
            envelope = json.loads(m["Body"])
            payload = json.loads(envelope["Message"])
            out.append({"envelope": envelope, "payload": payload})
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
        return out

    # SNS is at-least-once, so a duplicate is legal; what is asserted is that the queue (private
    # to this check) received the OK -> ALARM notification and nothing about another alarm.
    received: list[dict] = []

    def _transition_notes() -> list[dict]:
        received.extend(_drain())
        return [r for r in received if (r["payload"].get("OldStateValue"),
                                        r["payload"].get("NewStateValue")) == ("OK", "ALARM")]

    notes = _poll_until(ctx, _transition_notes, lambda n: len(n) >= 1, timeout_s=180.0,
                        interval_s=1.0,
                        description=f"an OK -> ALARM SNS notification for {alarm} in {queue_name}")
    foreign = [r["payload"].get("AlarmName") for r in received if r["payload"].get("AlarmName") != alarm]
    assert not foreign, f"queue received notifications for other alarms {foreign!r}"
    envelope, payload = notes[-1]["envelope"], notes[-1]["payload"]
    assert envelope.get("Type") == "Notification", f"SNS envelope type {envelope.get('Type')!r}"
    assert envelope.get("TopicArn") == topic_arn, f"envelope TopicArn {envelope.get('TopicArn')!r}"
    assert payload.get("AlarmName") == alarm, f"notification names alarm {payload.get('AlarmName')!r}"
    trigger = payload.get("Trigger") or {}
    assert (trigger.get("MetricName"), trigger.get("Namespace")) == (_METRIC, _NS), f"Trigger {trigger!r}"
    assert str(trigger.get("Statistic", "")).upper() == "MAXIMUM", f"Trigger.Statistic {trigger!r}"
    assert (trigger.get("Period"), trigger.get("EvaluationPeriods")) == (
        _PERIOD_S, _EVALUATION_PERIODS), f"Trigger period / evaluation periods {trigger!r}"
    assert float(trigger.get("Threshold")) == 1.0, f"Trigger.Threshold {trigger!r}"
    assert trigger.get("ComparisonOperator") == "LessThanThreshold", f"Trigger {trigger!r}"
    trigger_dims = {d.get("name") or d.get("Name"): d.get("value") or d.get("Value")
                    for d in trigger.get("Dimensions", [])}
    assert trigger_dims == {"ClusterName": cluster, "ServiceName": service}, (
        f"Trigger dimensions {trigger_dims!r}")


def _alarm(cw, name: str) -> dict:
    found = cw.describe_alarms(AlarmNames=[name], AlarmTypes=["MetricAlarm"])["MetricAlarms"]
    assert len(found) == 1, f"alarm {name!r} should be described exactly once, got {found!r}"
    return found[0]


def _unsubscribe(sns, arn: str) -> None:
    try:
        sns.unsubscribe(SubscriptionArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFound":
            raise


def _delete_cluster(ecs, cluster: str) -> None:
    try:
        ecs.delete_cluster(cluster=cluster)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise


def _poll_until(ctx, probe, predicate, *, timeout_s, interval_s, description):
    """Poll to a condition; the deadline is capped by the run's remaining budget."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} did not happen within {timeout_s}s; last read {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
