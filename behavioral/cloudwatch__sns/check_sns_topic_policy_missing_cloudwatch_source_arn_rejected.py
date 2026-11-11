"""sns-topic-policy-missing-cloudwatch-source-arn-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "sns-topic-policy-missing-cloudwatch-source-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch", "sns"]


@tags("axis:negative-delivery", "cap:c7", "concern:eventing", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A topic policy whose aws:SourceArn condition does not match the alarm's ARN blocks the
    alarm's notification, while a twin topic whose condition matches it delivers the ALARM
    notification."""
    cw = ctx.client("cloudwatch")
    sns = ctx.client("sns")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    alarm_name = ctx.unique_name("sim2real-cwsns-srcarn-")
    alarm_arn = f"arn:aws:cloudwatch:{ctx.region}:{account_id}:alarm:{alarm_name}"
    bogus_arn = f"arn:aws:cloudwatch:{ctx.region}:{account_id}:alarm:not-{alarm_name}"

    topic_mismatch = _create_topic(ctx)
    queue_mismatch_url, queue_mismatch_arn = _create_queue(ctx)
    _subscribe_queue(ctx, topic_mismatch, queue_mismatch_url, queue_mismatch_arn)
    _allow_cloudwatch_publish(
        ctx, topic_mismatch, condition={"ArnEquals": {"aws:SourceArn": bogus_arn}}
    )

    topic_match = _create_topic(ctx)
    queue_match_url, queue_match_arn = _create_queue(ctx)
    _subscribe_queue(ctx, topic_match, queue_match_url, queue_match_arn)
    _allow_cloudwatch_publish(
        ctx, topic_match, condition={"ArnEquals": {"aws:SourceArn": alarm_arn}}
    )

    # Sanity: the mismatch topic's policy really does scope to a different ARN.
    mismatch_policy = json.loads(sns.get_topic_attributes(TopicArn=topic_mismatch)["Attributes"]["Policy"])
    condition = mismatch_policy["Statement"][0]["Condition"]["ArnEquals"]["aws:SourceArn"]
    assert condition == bogus_arn and condition != alarm_arn

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace="sim2real/cwsns",
        MetricName=ctx.unique_name("metric-"),
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
        AlarmActions=[topic_match, topic_mismatch],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    described_arn = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["AlarmArn"]
    assert described_arn == alarm_arn

    cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason="sim2real test")

    payload = _poll_until_message(
        ctx, queue_match_url, lambda p: p.get("AlarmName") == alarm_name, timeout_s=90.0
    )
    assert payload["NewStateValue"] == "ALARM"

    seen = _drain_for(ctx, queue_mismatch_url, timeout_s=45.0)
    assert not any(p.get("AlarmName") == alarm_name for p in seen)


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-cwsns-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_topic(ctx) -> str:
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=ctx.unique_name("sim2real-cwsns-topic-"))["TopicArn"]
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


def _allow_cloudwatch_publish(ctx, topic_arn: str, condition: dict) -> None:
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
                "Condition": condition,
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


def _drain_for(ctx, queue_url: str, *, timeout_s: float, interval_s: float = 3.0) -> list[dict]:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    out: list[dict] = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            try:
                envelope = json.loads(m["Body"])
                payload = json.loads(envelope["Message"])
            except (KeyError, ValueError, json.JSONDecodeError):
                continue
            out.append(payload)
        time.sleep(interval_s)
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
