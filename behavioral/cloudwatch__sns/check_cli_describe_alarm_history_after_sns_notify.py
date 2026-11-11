"""cli-describe-alarm-history-after-sns-notify."""
from __future__ import annotations

import json
import subprocess
import time

from behavioral_harness import tags

CHECK = "cli-describe-alarm-history-after-sns-notify"
GROUP = "alerting"
SERVICES = ["cloudwatch", "sns"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """After an alarm-triggered SNS notification, `aws cloudwatch describe-alarm-history`
    shows the corresponding StateUpdate history item plus a recorded Action item for
    the SNS publish."""
    from fidelity_tests_runner import require_tools

    require_tools("aws")

    cw = ctx.client("cloudwatch")
    topic_arn = _create_topic(ctx)
    queue_url, queue_arn = _create_queue(ctx)
    _subscribe_queue(ctx, topic_arn, queue_url, queue_arn)
    _allow_cloudwatch_publish(ctx, topic_arn)

    alarm_name = ctx.unique_name("sim2real-cwsns-history-")
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
        AlarmActions=[topic_arn],
        Tags=_managed_tags_kv(),
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason="sim2real cli history test")

    # Confirm SNS actually delivered before inspecting history.
    payload = _poll_until_message(
        ctx, queue_url, lambda p: p.get("AlarmName") == alarm_name, timeout_s=90.0
    )
    assert payload["NewStateValue"] == "ALARM", (
        f"expected the delivered SNS notification to carry NewStateValue=ALARM, got {payload.get('NewStateValue')!r}"
    )

    env = ctx.subprocess_env()
    state_result = subprocess.run(
        [
            "aws", "cloudwatch", "describe-alarm-history",
            "--alarm-name", alarm_name,
            "--history-item-type", "StateUpdate",
            "--region", ctx.region,
            "--output", "json",
        ],
        env=env,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    state_items = json.loads(state_result.stdout)["AlarmHistoryItems"]
    matching = [
        item
        for item in state_items
        if json.loads(item["HistoryData"]).get("newState", {}).get("stateValue") == "ALARM"
    ]
    assert len(matching) >= 1, (
        f"expected a StateUpdate history item recording the transition to ALARM for "
        f"{alarm_name!r}, found none among {len(state_items)} StateUpdate items"
    )

    action_result = subprocess.run(
        [
            "aws", "cloudwatch", "describe-alarm-history",
            "--alarm-name", alarm_name,
            "--history-item-type", "Action",
            "--region", ctx.region,
            "--output", "json",
        ],
        env=env,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    action_items = json.loads(action_result.stdout)["AlarmHistoryItems"]
    assert len(action_items) >= 1, (
        f"expected an Action history item recording the SNS publish for {alarm_name!r}, found none"
    )
    assert any(topic_arn in item["HistorySummary"] or topic_arn in item["HistoryData"] for item in action_items), (
        f"expected an Action history item naming the invoked topic {topic_arn!r}, "
        f"got {[item['HistorySummary'] for item in action_items]!r}"
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
