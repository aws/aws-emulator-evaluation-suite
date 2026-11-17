"""notification-config-queue-and-topic-filters-roundtrip-and-delivery."""

from __future__ import annotations

import json
import time
from urllib.parse import unquote_plus

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "notification-config-queue-and-topic-filters-roundtrip-and-delivery"
GROUP = "notifications"
SERVICES = ["s3", "sns", "sqs"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` codes mean
    the resource is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    """Purge every object/version/delete-marker, then delete the bucket."""
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        targets = [
            {"Key": o["Key"], "VersionId": o["VersionId"]}
            for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
        ]
        if targets:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": targets})
    s3.delete_bucket(Bucket=bucket)


def _new_bucket(ctx, s3) -> str:
    """Create a uniquely-named, tagged bucket; register empty+delete teardown."""
    name = ctx.unique_name("sim2real-xsvc-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(_teardown(lambda: _empty_and_delete_bucket(s3, name), "NoSuchBucket"))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _new_queue(ctx, sqs, bucket: str) -> tuple[str, str]:
    """Create a uniquely-named queue, permit S3 to send to it, tag it, register teardown."""
    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-xsvc-q-"))["QueueUrl"]
    ctx.on_cleanup(
        _teardown(
            lambda: sqs.delete_queue(QueueUrl=queue_url),
            "AWS.SimpleQueueService.NonExistentQueue",
            "QueueDoesNotExist",
        )
    )
    sqs.tag_queue(QueueUrl=queue_url, Tags={"sim2real": CHECK})
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "s3.amazonaws.com"},
                    "Action": "sqs:SendMessage",
                    "Resource": queue_arn,
                    "Condition": {"ArnEquals": {"aws:SourceArn": f"arn:aws:s3:::{bucket}"}},
                }
            ],
        }
    )
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": policy})
    return queue_url, queue_arn


def _new_topic(ctx, sns, bucket: str) -> str:
    """Create a uniquely-named topic, permit S3 to publish to it, tag it, register teardown."""
    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-xsvc-t-"), Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["TopicArn"]
    ctx.on_cleanup(_teardown(lambda: sns.delete_topic(TopicArn=topic_arn), "NotFound"))
    policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "s3.amazonaws.com"},
                    "Action": "SNS:Publish",
                    "Resource": topic_arn,
                    "Condition": {"ArnEquals": {"aws:SourceArn": f"arn:aws:s3:::{bucket}"}},
                }
            ],
        }
    )
    sns.set_topic_attributes(TopicArn=topic_arn, AttributeName="Policy", AttributeValue=policy)
    return topic_arn


def _drain_until(sqs, queue_url: str, want_keys: set, *, budget_s: float) -> list:
    """Receive-and-delete every real (non ``s3:TestEvent``) S3 record for up to ``budget_s``,
    stopping early once every key in ``want_keys`` has been seen. Returns every
    ``(configurationId, eventName, bucket, key)`` tuple observed, so a late or stray delivery is
    quoted rather than missed."""
    records: list = []
    deadline = time.monotonic() + budget_s
    seen_keys: set = set()
    while time.monotonic() < deadline and not want_keys <= seen_keys:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            body = json.loads(msg["Body"])
            if body.get("Event") == "s3:TestEvent":
                continue
            for rec in body.get("Records", []):
                key = unquote_plus(rec["s3"]["object"]["key"])
                records.append((rec["s3"]["configurationId"], rec["eventName"], rec["s3"]["bucket"]["name"], key))
                seen_keys.add(key)
    return records


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:representation",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A queue config and a topic config applied together keep separate, exact Ids, Events and
    FilterRules (an explicitly empty prefix kept as ''); the queue delivers only the key matching
    both its rules, withholds a key that breaks one, and clearing the config drops both.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketNotificationConfiguration.html
    """
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")

    bucket = _new_bucket(ctx, s3)
    queue_url, queue_arn = _new_queue(ctx, sqs, bucket)
    topic_arn = _new_topic(ctx, sns, bucket)

    queue_id = "incoming-csv-to-queue"
    topic_id = "removed-txt-to-topic"
    s3.put_bucket_notification_configuration(
        Bucket=bucket,
        NotificationConfiguration={
            "QueueConfigurations": [
                {
                    "Id": queue_id,
                    "QueueArn": queue_arn,
                    "Events": ["s3:ObjectCreated:*"],
                    "Filter": {
                        "Key": {
                            "FilterRules": [
                                {"Name": "prefix", "Value": "incoming/"},
                                {"Name": "suffix", "Value": ".csv"},
                            ]
                        }
                    },
                }
            ],
            "TopicConfigurations": [
                {
                    "Id": topic_id,
                    "TopicArn": topic_arn,
                    "Events": ["s3:ObjectRemoved:*"],
                    "Filter": {
                        "Key": {
                            "FilterRules": [
                                {"Name": "prefix", "Value": ""},
                                {"Name": "suffix", "Value": ".txt"},
                            ]
                        }
                    },
                }
            ],
        },
    )

    configured = s3.get_bucket_notification_configuration(Bucket=bucket)
    queues = configured.get("QueueConfigurations", [])
    topics = configured.get("TopicConfigurations", [])
    assert len(queues) == 1, f"expected exactly one QueueConfigurations entry, got {queues!r}"
    assert len(topics) == 1, f"expected exactly one TopicConfigurations entry, got {topics!r}"
    q, t = queues[0], topics[0]

    assert q["Id"] == queue_id, f"expected queue Id {queue_id!r}, got {q['Id']!r}"
    assert q["QueueArn"] == queue_arn, f"expected QueueArn {queue_arn!r}, got {q['QueueArn']!r}"
    assert q["Events"] == ["s3:ObjectCreated:*"], (
        f"expected queue Events ['s3:ObjectCreated:*'], got {q['Events']!r}"
    )
    q_rules = q["Filter"]["Key"]["FilterRules"]
    assert q_rules == [{"Name": "Prefix", "Value": "incoming/"}, {"Name": "Suffix", "Value": ".csv"}], (
        f"expected queue FilterRules [Prefix='incoming/', Suffix='.csv'], got {q_rules!r}"
    )

    assert t["Id"] == topic_id, f"expected topic Id {topic_id!r}, got {t['Id']!r}"
    assert t["TopicArn"] == topic_arn, f"expected TopicArn {topic_arn!r}, got {t['TopicArn']!r}"
    assert t["Events"] == ["s3:ObjectRemoved:*"], (
        f"expected topic Events ['s3:ObjectRemoved:*'], got {t['Events']!r}"
    )
    t_rules = t["Filter"]["Key"]["FilterRules"]
    assert t_rules == [{"Name": "Prefix", "Value": ""}, {"Name": "Suffix", "Value": ".txt"}], (
        f"expected topic FilterRules [Prefix='', Suffix='.txt'] with the empty prefix kept, got {t_rules!r}"
    )

    # No wanted keys, so this returns at once; _drain_until skips the s3:TestEvent records.
    _drain_until(sqs, queue_url, set(), budget_s=20)

    # --- Delivered: a key matching both the queue's prefix and suffix.
    delivered_key = "incoming/a.csv"
    s3.put_object(Bucket=bucket, Key=delivered_key, Body=b"a,b\n1,2\n")
    first = _drain_until(sqs, queue_url, {delivered_key}, budget_s=60)
    matches = [r for r in first if r[3] == delivered_key]
    assert len(matches) == 1, f"expected exactly one delivery for {delivered_key!r}, got {first!r}"
    config_id, event_name, rec_bucket, _ = matches[0]
    assert config_id == queue_id, f"expected configurationId {queue_id!r}, got {config_id!r}"
    assert event_name == "ObjectCreated:Put", f"expected eventName 'ObjectCreated:Put', got {event_name!r}"
    assert rec_bucket == bucket, f"expected record bucket {bucket!r}, got {rec_bucket!r}"

    # --- Withheld: a key under the same prefix but the wrong suffix, proven absent against two
    # later, known-good deliveries rather than a bare quiet window. If the withheld key had been
    # (incorrectly) sent, it was written before either control and would already be visible by
    # the time both controls, written after it, have arrived.
    withheld_key = "incoming/a.txt"
    s3.put_object(Bucket=bucket, Key=withheld_key, Body=b"not csv")
    control_keys = {"incoming/b.csv", "incoming/c.csv"}
    for key in sorted(control_keys):
        s3.put_object(Bucket=bucket, Key=key, Body=b"c,d\n3,4\n")
    seen = _drain_until(sqs, queue_url, control_keys, budget_s=60)
    seen_keys = {r[3] for r in seen}
    assert control_keys <= seen_keys, (
        f"the later positive controls {sorted(control_keys)} never all arrived within budget; saw {sorted(seen_keys)!r}"
    )
    assert withheld_key not in seen_keys, (
        f"{withheld_key!r} does not match the queue's .csv suffix filter but was delivered: {seen!r}"
    )

    # --- Clear: an empty NotificationConfiguration drops every configuration key.
    s3.put_bucket_notification_configuration(Bucket=bucket, NotificationConfiguration={})
    cleared = s3.get_bucket_notification_configuration(Bucket=bucket)
    config_keys = set(cleared) - {"ResponseMetadata"}
    assert config_keys == set(), f"expected no configuration keys after clearing, got {sorted(config_keys)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
