"""composite-alarm-notifies-sns."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "composite-alarm-notifies-sns"
GROUP = "alerting"
SERVICES = ["cloudwatch", "sns"]


@tags("axis:happy-path", "cap:c4", "concern:eventing", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A composite alarm transitioning to ALARM (via its child's real state) publishes to SNS."""
    cw = ctx.client("cloudwatch")
    topic_arn = _create_topic(ctx)
    queue_url, queue_arn = _create_queue(ctx)
    _subscribe_queue(ctx, topic_arn, queue_url, queue_arn)
    _allow_cloudwatch_publish(ctx, topic_arn)

    child_name = ctx.unique_name("sim2real-cwsns-child-")
    cw.put_metric_alarm(
        AlarmName=child_name,
        Namespace="sim2real/cwsns",
        MetricName=ctx.unique_name("metric-"),
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[child_name]))

    composite_name = ctx.unique_name("sim2real-cwsns-composite-")
    cw.put_composite_alarm(
        AlarmName=composite_name,
        AlarmRule=f'ALARM("{child_name}")',
        AlarmActions=[topic_arn],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[composite_name]))

    # Force the child alarm into ALARM. The composite alarm must re-evaluate its
    # rule from the child's actual tracked state and transition itself.
    cw.set_alarm_state(AlarmName=child_name, StateValue="ALARM", StateReason="sim2real test")

    _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[composite_name], AlarmTypes=["CompositeAlarm"])[
            "CompositeAlarms"
        ][0]["StateValue"],
        lambda state: state == "ALARM",
        timeout_s=90.0,
        interval_s=3.0,
    )

    payload = _poll_until_message(
        ctx, queue_url, lambda p: p.get("AlarmName") == composite_name, timeout_s=90.0
    )
    assert payload["NewStateValue"] == "ALARM", (
        f"expected composite alarm notification NewStateValue 'ALARM', got {payload['NewStateValue']!r}"
    )
    assert payload["AlarmRule"] == f'ALARM("{child_name}")', (
        f"expected AlarmRule ALARM(\"{child_name}\"), got {payload['AlarmRule']!r}"
    )
    triggering_children = payload.get("TriggeringChildren", [])
    assert any(child_name in str(tc) for tc in triggering_children), (
        f"expected {child_name} among TriggeringChildren, got {triggering_children!r}"
    )


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


def _allow_cloudwatch_publish(ctx, topic_arn: str, condition: dict[str, Any] | None = None) -> None:
    sns = ctx.client("sns")
    stmt = {
        "Sid": "AllowCloudWatchPublish",
        "Effect": "Allow",
        "Principal": {"Service": "cloudwatch.amazonaws.com"},
        "Action": "SNS:Publish",
        "Resource": topic_arn,
    }
    if condition:
        stmt["Condition"] = condition
    policy = {"Version": "2012-10-17", "Statement": [stmt]}
    sns.set_topic_attributes(TopicArn=topic_arn, AttributeName="Policy", AttributeValue=json.dumps(policy))


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


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
