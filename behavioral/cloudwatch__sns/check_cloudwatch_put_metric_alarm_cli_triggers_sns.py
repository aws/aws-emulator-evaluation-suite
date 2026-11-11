"""cloudwatch-put-metric-alarm-cli-triggers-sns."""
from __future__ import annotations

import json
import subprocess
import time

from behavioral_harness import tags

CHECK = "cloudwatch-put-metric-alarm-cli-triggers-sns"
GROUP = "alerting"
SERVICES = ["cloudwatch", "sns"]

_TAG_KV = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-cwsns"}]


@tags("axis:happy-path", "cap:c1", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Driving put-metric-alarm and set-alarm-state through the aws CLI produces an
    observable SNS publish, verified independently via the SDK."""
    from fidelity_tests_runner import require_tools

    require_tools("aws")

    cw = ctx.client("cloudwatch")
    topic_arn = _create_topic(ctx)
    queue_url, queue_arn = _create_queue(ctx)
    _subscribe_queue(ctx, topic_arn, queue_url, queue_arn)
    _allow_cloudwatch_publish(ctx, topic_arn)

    alarm_name = ctx.unique_name("sim2real-cwsns-cli-")
    metric_name = ctx.unique_name("metric-")
    env = ctx.subprocess_env()

    subprocess.run(
        [
            "aws", "cloudwatch", "put-metric-alarm",
            "--alarm-name", alarm_name,
            "--namespace", "sim2real/cwsns",
            "--metric-name", metric_name,
            "--statistic", "Average",
            "--period", "60",
            "--evaluation-periods", "1",
            "--threshold", "1",
            "--comparison-operator", "GreaterThanThreshold",
            "--treat-missing-data", "notBreaching",
            "--alarm-actions", topic_arn,
            "--tags", "Key=sim2real:managed,Value=true", "Key=sim2real:prefix,Value=sim2real-cwsns",
            "--region", ctx.region,
        ],
        env=env,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    subprocess.run(
        [
            "aws", "cloudwatch", "set-alarm-state",
            "--alarm-name", alarm_name,
            "--state-value", "ALARM",
            "--state-reason", "sim2real cli test",
            "--region", ctx.region,
        ],
        env=env,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )

    described = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]
    assert described["MetricName"] == metric_name, (
        f"expected MetricName {metric_name!r} on the CLI-created alarm, got {described['MetricName']!r}"
    )
    assert described["AlarmActions"] == [topic_arn], (
        f"expected AlarmActions [{topic_arn!r}], got {described['AlarmActions']!r}"
    )

    payload = _poll_until_message(
        ctx, queue_url, lambda p: p.get("AlarmName") == alarm_name, timeout_s=90.0
    )
    assert payload["NewStateValue"] == "ALARM", (
        f"expected the SNS notification's NewStateValue to be ALARM, got {payload['NewStateValue']!r}"
    )


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-cwsns-q-"),
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-cwsns"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_topic(ctx) -> str:
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=ctx.unique_name("sim2real-cwsns-topic-"), Tags=_TAG_KV)["TopicArn"]
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
