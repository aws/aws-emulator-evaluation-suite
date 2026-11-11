"""metric-filter-log-group-alarm-notifies-sns."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "metric-filter-log-group-alarm-notifies-sns"
GROUP = "alerting"
SERVICES = ["cloudwatch", "sns"]

_MANAGED_TAGS = {"sim2real:managed": "true"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:e2e", "concern:eventing", "concern:metrics", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudWatch Logs metric filter correctly wires a log group's metric to a
    metric alarm; when that alarm transitions to ALARM it delivers a notification to
    the subscribed SNS topic."""
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")

    log_group = ctx.unique_name("/sim2real/cwsns/")
    logs.create_log_group(logGroupName=log_group, tags=_MANAGED_TAGS)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    filter_name = ctx.unique_name("sim2real-cwsns-filter-")
    metric_name = ctx.unique_name("errors-")
    namespace = "sim2real/cwsns/logs"
    logs.put_metric_filter(
        logGroupName=log_group,
        filterName=filter_name,
        filterPattern="ERROR",
        metricTransformations=[
            {
                "metricName": metric_name,
                "metricNamespace": namespace,
                "metricValue": "1",
                "defaultValue": 0,
            }
        ],
    )
    ctx.on_cleanup(lambda: logs.delete_metric_filter(logGroupName=log_group, filterName=filter_name))

    # Control-plane wiring check: the filter really targets the namespace/metric we
    # are about to alarm on.
    filters = logs.describe_metric_filters(logGroupName=log_group, filterNamePrefix=filter_name)[
        "metricFilters"
    ]
    assert len(filters) == 1, f"expected exactly 1 metric filter named {filter_name}, got {filters!r}"
    transform = filters[0]["metricTransformations"][0]
    assert transform["metricName"] == metric_name, (
        f"expected metricName {metric_name!r}, got {transform['metricName']!r}"
    )
    assert transform["metricNamespace"] == namespace, (
        f"expected metricNamespace {namespace!r}, got {transform['metricNamespace']!r}"
    )

    topic_arn = _create_topic(ctx)
    queue_url, queue_arn = _create_queue(ctx)
    _subscribe_queue(ctx, topic_arn, queue_url, queue_arn)
    _allow_cloudwatch_publish(ctx, topic_arn)

    alarm_name = ctx.unique_name("sim2real-cwsns-logalarm-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName=metric_name,
        Statistic="Sum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanOrEqualToThreshold",
        TreatMissingData="notBreaching",
        AlarmActions=[topic_arn],
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    described = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]
    assert described["Namespace"] == namespace, (
        f"alarm {alarm_name} expected Namespace {namespace!r}, got {described['Namespace']!r}"
    )
    assert described["MetricName"] == metric_name, (
        f"alarm {alarm_name} expected MetricName {metric_name!r}, got {described['MetricName']!r}"
    )

    cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason="sim2real test")

    payload = _poll_until_message(
        ctx, queue_url, lambda p: p.get("AlarmName") == alarm_name, timeout_s=90.0
    )
    assert payload["NewStateValue"] == "ALARM", (
        f"expected NewStateValue 'ALARM' in the SNS notification, got {payload['NewStateValue']!r}"
    )
    assert payload["Trigger"]["Namespace"] == namespace, (
        f"expected Trigger.Namespace {namespace!r} (the filter's namespace), "
        f"got {payload['Trigger']['Namespace']!r}"
    )
    assert payload["Trigger"]["MetricName"] == metric_name, (
        f"expected Trigger.MetricName {metric_name!r} (the filter's metric), "
        f"got {payload['Trigger']['MetricName']!r}"
    )


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-cwsns-q-"), tags=_MANAGED_TAGS)[
        "QueueUrl"
    ]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_topic(ctx) -> str:
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-cwsns-topic-"),
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


def _subscribe_queue(ctx, topic_arn: str, queue_url: str, queue_arn: str) -> str:
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowSNS",
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))
    return sub_arn


def _allow_cloudwatch_publish(ctx, topic_arn: str) -> None:
    sns = ctx.client("sns")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowCloudWatchPublish",
                "Effect": "Allow",
                "Principal": {"Service": "cloudwatch.amazonaws.com"},
                "Action": "SNS:Publish",
                "Resource": topic_arn,
            }
        ],
    }
    sns.set_topic_attributes(TopicArn=topic_arn, AttributeName="Policy", AttributeValue=json.dumps(policy))


def _poll_until_message(ctx, queue_url: str, predicate, *, timeout_s: float, interval_s: float = 3.0) -> dict:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            try:
                envelope = json.loads(m["Body"])
                payload = json.loads(envelope["Message"])
            except (KeyError, ValueError, json.JSONDecodeError):
                continue
            if predicate(payload):
                return payload
        time.sleep(interval_s)
    raise AssertionError(f"no matching alarm notification arrived within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
