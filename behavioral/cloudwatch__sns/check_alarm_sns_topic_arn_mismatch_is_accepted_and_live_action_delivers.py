"""alarm-sns-topic-arn-mismatch-is-accepted-and-live-action-delivers."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "alarm-sns-topic-arn-mismatch-is-accepted-and-live-action-delivers"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch", "sns"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutMetricAlarm accepts an action on a deleted SNS topic; on ALARM the history records that
    action Failed with 'Topic does not exist' and the live topic's action Succeeded, and the live
    topic's notification arrives."""
    cw = ctx.client("cloudwatch")
    sns = ctx.client("sns")

    topic_valid = _create_topic(ctx)
    queue_url, queue_arn = _create_queue(ctx)
    _subscribe_queue(ctx, topic_valid, queue_url, queue_arn)
    _allow_cloudwatch_publish(ctx, topic_valid)

    # Create then immediately delete a second topic -> a stale ARN that no longer exists.
    topic_stale = sns.create_topic(Name=ctx.unique_name("sim2real-cwsns-stale-"))["TopicArn"]
    sns.delete_topic(TopicArn=topic_stale)

    err = _error(lambda: sns.get_topic_attributes(TopicArn=topic_stale))
    assert err == ("NotFound", "Topic does not exist"), (
        f"expected the deleted topic to read back ('NotFound', 'Topic does not exist'), got {err!r}"
    )

    alarm_name = ctx.unique_name("sim2real-cwsns-stalearn-")
    # PutMetricAlarm does not validate that action ARNs currently exist -- this call
    # succeeding at all (no ClientError raised) is the "accepted" half of the claim.
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
        AlarmActions=[topic_valid, topic_stale],
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason="sim2real test")

    payload = _poll_until_message(
        ctx, queue_url, lambda p: p.get("AlarmName") == alarm_name, timeout_s=90.0
    )
    assert payload["NewStateValue"] == "ALARM", (
        f"expected the live-topic notification to carry NewStateValue=ALARM, got {payload!r}"
    )
    assert topic_stale in payload["AlarmActions"], (
        f"expected the configured stale ARN {topic_stale!r} to still be echoed in "
        f"AlarmActions={payload['AlarmActions']!r} -- this by itself is not proof of "
        f"non-delivery, which is why the Action history is checked below"
    )

    # The queue subscription proves the live topic delivered. It cannot prove the stale
    # topic did NOT deliver -- nothing is subscribed to a topic that no longer exists.
    # CloudWatch's own Action history is the independent, destination-side record of
    # what the dispatcher actually did with each ARN.
    actions = _poll_until(
        lambda: _action_history(cw, alarm_name),
        lambda items: any(i.get("actionState") == "Failed" for i in items)
        and any(i.get("actionState") == "Succeeded" for i in items),
        timeout_s=60.0,
        interval_s=5.0,
    )
    failed = [i for i in actions if i.get("actionState") == "Failed"]
    succeeded = [i for i in actions if i.get("actionState") == "Succeeded"]
    assert failed, f"no Failed action item was recorded for the stale ARN; items were {actions!r}"
    assert succeeded, f"no Succeeded action item was recorded for the live ARN; items were {actions!r}"
    assert {i.get("notificationResource") for i in failed} == {topic_stale}, (
        f"expected only the stale topic {topic_stale!r} to be recorded Failed, got "
        f"{[i.get('notificationResource') for i in failed]!r}"
    )
    assert {i.get("notificationResource") for i in succeeded} == {topic_valid}, (
        f"expected only the live topic {topic_valid!r} to be recorded Succeeded, got "
        f"{[i.get('notificationResource') for i in succeeded]!r}"
    )
    assert failed[0].get("publishedMessage") is None, (
        f"a Failed dispatch to the deleted topic still reported a publishedMessage: {failed[0]!r}"
    )
    assert failed[0].get("error") == "Topic does not exist", (
        f"expected the Failed action item to carry error 'Topic does not exist', got {failed[0]!r}"
    )


def _error(fn) -> tuple[str, str]:
    """The AWS (code, message) *fn* raised. Raises if it succeeded, so success is never a code."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("call succeeded but an error was expected")


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-cwsns-q-"), tags={"sim2real:managed": "true"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_topic(ctx) -> str:
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-cwsns-topic-"),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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


def _action_history(cw, alarm_name: str) -> list[dict]:
    """Every Action history item for the alarm, parsed from its JSON HistoryData."""
    items = []
    for page in cw.get_paginator("describe_alarm_history").paginate(
        AlarmName=alarm_name, HistoryItemType="Action", ScanBy="TimestampDescending"
    ):
        for item in page.get("AlarmHistoryItems", []):
            try:
                items.append(json.loads(item["HistoryData"]))
            except (ValueError, TypeError, KeyError):
                items.append({"unparsable": item.get("HistoryData")})
    return items


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition not met within {timeout_s}s; last observation {last!r}"
            )
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
