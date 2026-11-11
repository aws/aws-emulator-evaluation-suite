"""cloudwatch-alarm-sns-kms-key-policy-missing-no-delivery-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "cloudwatch-alarm-sns-kms-key-policy-missing-no-delivery-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch", "sns"]


@tags("axis:negative-delivery", "cap:c7", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An alarm notification to an SNS topic encrypted with a KMS key whose policy grants CloudWatch
    nothing is never delivered, while a topic whose key grants it delivers the ALARM
    notification."""
    cw = ctx.client("cloudwatch")
    kms = ctx.client("kms")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    root_principal = f"arn:aws:iam::{account_id}:root"

    key_bad = _create_kms_key(
        ctx,
        kms,
        [
            {
                "Sid": "EnableRootAccess",
                "Effect": "Allow",
                "Principal": {"AWS": root_principal},
                "Action": "kms:*",
                "Resource": "*",
            }
        ],
    )
    key_good = _create_kms_key(
        ctx,
        kms,
        [
            {
                "Sid": "EnableRootAccess",
                "Effect": "Allow",
                "Principal": {"AWS": root_principal},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "AllowCloudWatchToUseKey",
                "Effect": "Allow",
                "Principal": {"Service": "cloudwatch.amazonaws.com"},
                "Action": ["kms:GenerateDataKey*", "kms:Decrypt"],
                "Resource": "*",
            },
        ],
    )

    # Sanity: confirm key_bad's policy really grants cloudwatch no access.
    bad_key_policy = json.loads(kms.get_key_policy(KeyId=key_bad, PolicyName="default")["Policy"])
    granting_statements = [s for s in bad_key_policy["Statement"] if _grants_cloudwatch(s)]
    assert not granting_statements, (
        f"expected key_bad's policy to grant cloudwatch.amazonaws.com no access, "
        f"found granting statements: {granting_statements}"
    )

    topic_bad = _create_topic(ctx, kms_key_id=key_bad)
    queue_bad_url, queue_bad_arn = _create_queue(ctx)
    _subscribe_queue(ctx, topic_bad, queue_bad_url, queue_bad_arn)
    _allow_cloudwatch_publish(ctx, topic_bad)

    topic_good = _create_topic(ctx, kms_key_id=key_good)
    queue_good_url, queue_good_arn = _create_queue(ctx)
    _subscribe_queue(ctx, topic_good, queue_good_url, queue_good_arn)
    _allow_cloudwatch_publish(ctx, topic_good)

    alarm_name = ctx.unique_name("sim2real-cwsns-kms-")
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
        AlarmActions=[topic_good, topic_bad],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason="sim2real test")

    payload = _poll_until_message(
        ctx, queue_good_url, lambda p: p.get("AlarmName") == alarm_name, timeout_s=90.0
    )
    assert payload["NewStateValue"] == "ALARM", (
        f"positive control: expected NewStateValue ALARM, got {payload.get('NewStateValue')!r}"
    )

    seen = _drain_for(ctx, queue_bad_url, timeout_s=45.0)
    matching = [p for p in seen if p.get("AlarmName") == alarm_name]
    assert not matching, (
        f"expected NO delivery to the topic encrypted with a key that denies cloudwatch "
        f"kms:GenerateDataKey*/kms:Decrypt, but saw: {matching}"
    )


def _grants_cloudwatch(stmt: dict) -> bool:
    principal = stmt.get("Principal", {})
    service = principal.get("Service") if isinstance(principal, dict) else None
    services = [service] if isinstance(service, str) else (service or [])
    return stmt.get("Effect") == "Allow" and "cloudwatch.amazonaws.com" in services


def _create_kms_key(ctx, kms, statements: list[dict]) -> str:
    policy = {"Version": "2012-10-17", "Id": "sim2real-cwsns-key-policy", "Statement": statements}
    key_id = kms.create_key(
        Description=ctx.unique_name("sim2real-cwsns-key-"),
        Policy=json.dumps(policy),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return key_id


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-cwsns-q-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_topic(ctx, kms_key_id: str) -> str:
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-cwsns-topic-"),
        Attributes={"KmsMasterKeyId": kms_key_id},
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
