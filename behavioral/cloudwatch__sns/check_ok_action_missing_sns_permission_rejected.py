"""ok-action-missing-sns-permission-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "ok-action-missing-sns-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch", "sns"]

_MANAGED_TAG_KEY = "sim2real:managed"


def _managed_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:check": CHECK}


def _managed_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _managed_tags().items()]


@tags("axis:negative-delivery", "cap:c4", "cap:c7", "concern:eventing", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """An alarm OK action pointing at a topic whose policy does not grant
    cloudwatch.amazonaws.com sns:Publish is recorded as a Failed action and never gets delivered,
    while the same alarm's ALARM action on a properly-permissioned topic (positive control) does."""
    cw = ctx.client("cloudwatch")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    topic_good = _create_topic(ctx)
    queue_good_url, queue_good_arn = _create_queue(ctx)
    _subscribe_queue(ctx, topic_good, queue_good_url, queue_good_arn)
    _allow_cloudwatch_publish(ctx, topic_good)

    topic_bad = _create_topic(ctx)  # explicit policy that omits cloudwatch.amazonaws.com
    queue_bad_url, queue_bad_arn = _create_queue(ctx)
    _subscribe_queue(ctx, topic_bad, queue_bad_url, queue_bad_arn)
    # SNS's auto-generated default policy grants Publish to any principal whose
    # aws:SourceOwner matches the topic owner account -- which would let a
    # same-account CloudWatch alarm through even with no cloudwatch grant. Replace
    # it with an explicit policy scoped to the account root only, so no service
    # principal (including cloudwatch.amazonaws.com) is authorized to publish.
    _restrict_to_owner_only(ctx, topic_bad)

    # Sanity: confirm topic_bad's policy really grants no cloudwatch principal access.
    bad_policy = json.loads(sns.get_topic_attributes(TopicArn=topic_bad)["Attributes"]["Policy"])
    granting = [stmt for stmt in bad_policy.get("Statement", []) if _statement_grants_cloudwatch(stmt)]
    assert not granting, (
        f"expected topic_bad's policy to grant no cloudwatch.amazonaws.com principal, "
        f"found granting statement(s): {granting!r}"
    )

    alarm_name = ctx.unique_name("sim2real-cwsns-okperm-")
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
        AlarmActions=[topic_good],
        OKActions=[topic_bad],
        Tags=_managed_tags_kv(),
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason="sim2real test")
    payload = _poll_until_message(
        ctx, queue_good_url, lambda p: p.get("AlarmName") == alarm_name, timeout_s=90.0
    )
    assert payload["NewStateValue"] == "ALARM", (
        f"expected the positive control's delivered notification to carry NewStateValue=ALARM, "
        f"got {payload.get('NewStateValue')!r} (full payload: {payload!r})"
    )

    cw.set_alarm_state(AlarmName=alarm_name, StateValue="OK", StateReason="sim2real test")
    # The alarm's own state must still flip to OK...
    _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"],
        lambda s: s == "OK",
        timeout_s=30.0,
        interval_s=2.0,
    )
    # ...and the alarm records the OK action's publish attempt as Failed. That record is ordered
    # after the attempt, so the queue is read once it exists, never across a measured window.
    attempts = _poll_until(
        lambda: [
            h for h in cw.describe_alarm_history(
                AlarmName=alarm_name, HistoryItemType="Action"
            )["AlarmHistoryItems"]
            if topic_bad in h["HistorySummary"]
        ],
        bool,
        timeout_s=90.0,
        interval_s=3.0,
    )
    states = [json.loads(h["HistoryData"]).get("actionState") for h in attempts]
    assert states == ["Failed"] * len(states), (
        f"the OK action on the unpermissioned topic must be recorded as Failed, got actionState "
        f"{states!r} with data {[h['HistoryData'] for h in attempts]!r}"
    )
    seen = _receive_once(ctx, queue_bad_url)
    assert not any(p.get("AlarmName") == alarm_name for p in seen), (
        f"expected no OK-notification for {alarm_name!r} to reach the unpermissioned topic's "
        f"queue, but saw: {[p for p in seen if p.get('AlarmName') == alarm_name]!r}"
    )
    # Second, independent observable: the queue's own server-side count agrees with the drain.
    remaining = sqs.get_queue_attributes(
        QueueUrl=queue_bad_url, AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]["ApproximateNumberOfMessages"]
    assert remaining == "0", (
        f"expected ApproximateNumberOfMessages=='0' on the unpermissioned topic's queue after "
        f"draining, got {remaining!r}"
    )


def _statement_grants_cloudwatch(stmt: dict) -> bool:
    principal = stmt.get("Principal", {})
    service = principal.get("Service") if isinstance(principal, dict) else None
    services = [service] if isinstance(service, str) else (service or [])
    return stmt.get("Effect") == "Allow" and "cloudwatch.amazonaws.com" in services


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-cwsns-q-"), tags=_managed_tags()
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_topic(ctx) -> str:
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-cwsns-topic-"), Tags=_managed_tags_kv()
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


def _restrict_to_owner_only(ctx, topic_arn: str) -> None:
    sns = ctx.client("sns")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "OwnerAccountOnly",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "SNS:Publish",
                "Resource": topic_arn,
            }
        ],
    }
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
