"""multiple-alarms-fanout-single-sns-topic."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "multiple-alarms-fanout-single-sns-topic"
GROUP = "alerting"
SERVICES = ["cloudwatch", "sns"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """Three independent alarms sharing one SNS topic action each deliver their own
    distinct notification when they transition to ALARM."""
    cw = ctx.client("cloudwatch")
    topic_arn = _create_topic(ctx)
    queue_url, queue_arn = _create_queue(ctx)
    _subscribe_queue(ctx, topic_arn, queue_url, queue_arn)
    _allow_cloudwatch_publish(ctx, topic_arn)

    alarm_names = [ctx.unique_name(f"sim2real-cwsns-fanout{i}-") for i in range(3)]
    for name in alarm_names:
        cw.put_metric_alarm(
            AlarmName=name,
            Namespace="sim2real/cwsns",
            MetricName=ctx.unique_name("metric-"),
            Statistic="Average",
            Period=60,
            EvaluationPeriods=1,
            Threshold=1.0,
            ComparisonOperator="GreaterThanThreshold",
            TreatMissingData="notBreaching",
            AlarmActions=[topic_arn],
            Tags=_managed_tags_kv(),
        )
        ctx.on_cleanup(lambda n=name: cw.delete_alarms(AlarmNames=[n]))

    for name in alarm_names:
        cw.set_alarm_state(AlarmName=name, StateValue="ALARM", StateReason="sim2real test")

    received = _poll_until_all_names(ctx, queue_url, set(alarm_names), timeout_s=120.0)
    for name in alarm_names:
        assert name in received, f"expected a distinct notification for alarm {name!r}, got none of {sorted(received)}"
        assert received[name]["NewStateValue"] == "ALARM", (
            f"alarm {name!r}: expected NewStateValue=ALARM, got {received[name].get('NewStateValue')!r}"
        )
        assert received[name]["AlarmArn"].endswith(f":alarm:{name}"), (
            f"alarm {name!r}: expected AlarmArn ending ':alarm:{name}', got {received[name].get('AlarmArn')!r}"
        )


def _managed_tags() -> dict[str, str]:
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2real-cwsns"}


def _managed_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _managed_tags().items()]


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-cwsns-q-"), tags=_managed_tags())["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_topic(ctx) -> str:
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=ctx.unique_name("sim2real-cwsns-topic-"), Tags=_managed_tags_kv())["TopicArn"]
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


def _poll_until_all_names(ctx, queue_url: str, expected_names: set[str], *, timeout_s: float, interval_s: float = 3.0) -> dict:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    found: dict[str, dict] = {}
    while time.monotonic() < deadline and expected_names - found.keys():
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            try:
                envelope = json.loads(m["Body"])
                payload = json.loads(envelope["Message"])
            except (KeyError, ValueError, json.JSONDecodeError):
                continue
            name = payload.get("AlarmName")
            if name in expected_names:
                found[name] = payload
        time.sleep(interval_s)
    missing = expected_names - found.keys()
    if missing:
        raise AssertionError(f"never received notifications for alarms: {missing}")
    return found


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
