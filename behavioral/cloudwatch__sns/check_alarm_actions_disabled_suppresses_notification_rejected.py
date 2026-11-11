"""alarm-actions-disabled-suppresses-notification-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "alarm-actions-disabled-suppresses-notification-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch", "sns"]


@tags("axis:negative-delivery", "cap:c1", "concern:data-plane", "concern:eventing", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """ActionsEnabled=false suppresses the SNS publish even though the alarm state still
    transitions to ALARM; a sibling alarm with actions enabled on the same topic still
    delivers, proving the topic/subscription wiring itself is fine."""
    cw = ctx.client("cloudwatch")
    topic_arn = _create_topic(ctx)
    queue_url, queue_arn = _create_queue(ctx)
    _subscribe_queue(ctx, topic_arn, queue_url, queue_arn)
    _allow_cloudwatch_publish(ctx, topic_arn)

    disabled_name = ctx.unique_name("sim2real-cwsns-disabled-")
    enabled_name = ctx.unique_name("sim2real-cwsns-enabled-")
    for name, actions_enabled in ((disabled_name, False), (enabled_name, True)):
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
            ActionsEnabled=actions_enabled,
            AlarmActions=[topic_arn],
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        ctx.on_cleanup(lambda n=name: cw.delete_alarms(AlarmNames=[n]))

    # The disabled alarm transitions first, so the enabled alarm's notification is a positive
    # control ordered after any publish the disabled one could make on the same topic.
    cw.set_alarm_state(AlarmName=disabled_name, StateValue="ALARM", StateReason="sim2real test")
    cw.set_alarm_state(AlarmName=enabled_name, StateValue="ALARM", StateReason="sim2real test")

    payload, seen = _poll_until_message(
        ctx, queue_url, lambda p: p.get("AlarmName") == enabled_name, timeout_s=90.0
    )
    assert payload["NewStateValue"] == "ALARM", (
        f"expected NewStateValue ALARM in the enabled alarm's notification, got {payload!r}"
    )

    # The disabled alarm's state transition still happened...
    disabled_state = cw.describe_alarms(AlarmNames=[disabled_name])["MetricAlarms"][0]
    assert disabled_state["StateValue"] == "ALARM", (
        f"expected disabled alarm StateValue ALARM, got {disabled_state['StateValue']!r}"
    )
    assert disabled_state["ActionsEnabled"] is False, (
        f"expected disabled alarm ActionsEnabled False, got {disabled_state['ActionsEnabled']!r}"
    )

    # ...but no notification for it arrives before or with the positive control, nor in one
    # more receive round after it.
    seen += _receive_once(ctx, queue_url)
    assert not any(p.get("AlarmName") == disabled_name for p in seen), (
        f"the disabled alarm's notification reached the queue alongside the enabled alarm's: "
        f"{seen!r}"
    )

    # Second independent observable: the queue itself must report nothing pending, not just
    # an empty sample from our own receive loop.
    sqs = ctx.client("sqs")
    attrs = sqs.get_queue_attributes(
        QueueUrl=queue_url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    assert attrs["ApproximateNumberOfMessages"] == "0" and attrs["ApproximateNumberOfMessagesNotVisible"] == "0", (
        f"queue reports pending messages after the drain, expected both counters at 0: {attrs!r}"
    )


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-cwsns-q-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_topic(ctx) -> str:
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-cwsns-topic-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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


def _poll_until_message(
    ctx, queue_url: str, predicate, *, timeout_s: float, interval_s: float = 3.0
) -> tuple[dict, list[dict]]:
    """The first alarm payload predicate accepts, with every payload received up to it."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    seen: list[dict] = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            try:
                envelope = json.loads(m["Body"])
                payload = json.loads(envelope["Message"])
            except (KeyError, ValueError, json.JSONDecodeError):
                continue
            seen.append(payload)
            if predicate(payload):
                return payload, seen
        time.sleep(interval_s)
    raise AssertionError(f"no matching alarm notification arrived within {timeout_s}s")


def _receive_once(ctx, queue_url: str) -> list[dict]:
    """One receive round (a 5 s long poll), deleting what it reads; return the alarm payloads."""
    sqs = ctx.client("sqs")
    out: list[dict] = []
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
    for m in resp.get("Messages", []):
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
        try:
            envelope = json.loads(m["Body"])
            payload = json.loads(envelope["Message"])
        except (KeyError, ValueError, json.JSONDecodeError):
            continue
        out.append(payload)
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
