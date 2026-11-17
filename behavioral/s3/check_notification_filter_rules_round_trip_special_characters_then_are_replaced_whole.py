"""notification-filter-rules-round-trip-special-characters-then-are-replaced-whole."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "notification-filter-rules-round-trip-special-characters-then-are-replaced-whole"
GROUP = "notifications"
SERVICES = ["s3", "sqs"]

_FIRST_PREFIX = "incoming/t&m<1>/"
_FIRST_SUFFIX = "-été.csv"
_SECOND_PREFIX = "archive/文件/"
_SECOND_SUFFIX = ".json"


def _delete_bucket(s3, bucket: str) -> None:
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3) -> str:
    name = ctx.unique_name("sim2real-notifenc-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _queue_notifiable_by(ctx, sqs, bucket: str, name_prefix: str) -> str:
    """A queue whose policy lets `bucket` send it S3 events; returns its ARN. Teardown registered."""
    url = sqs.create_queue(QueueName=ctx.unique_name(name_prefix))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(
        QueueUrl=url,
        Attributes={"Policy": json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "s3.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": f"arn:aws:s3:::{bucket}"}},
            }],
        })},
    )
    return arn


def _filter_rules(config: dict) -> dict:
    return {r["Name"].lower(): r["Value"] for r in config["Filter"]["Key"]["FilterRules"]}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A notification filter's prefix/suffix round-trip reserved XML characters and non-ASCII
    text byte for byte, and a second PutBucketNotificationConfiguration replaces the entire
    configuration rather than adding to it."""
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    bucket = _new_bucket(ctx, s3)
    first_arn = _queue_notifiable_by(ctx, sqs, bucket, "sim2real-notifenc-q1-")
    second_arn = _queue_notifiable_by(ctx, sqs, bucket, "sim2real-notifenc-q2-")

    s3.put_bucket_notification_configuration(
        Bucket=bucket,
        NotificationConfiguration={
            "QueueConfigurations": [{
                "Id": "first",
                "QueueArn": first_arn,
                "Events": ["s3:ObjectCreated:*"],
                "Filter": {"Key": {"FilterRules": [
                    {"Name": "prefix", "Value": _FIRST_PREFIX},
                    {"Name": "suffix", "Value": _FIRST_SUFFIX},
                ]}},
            }]
        },
    )
    first_configs = s3.get_bucket_notification_configuration(Bucket=bucket).get("QueueConfigurations", [])
    first_entry = next((c for c in first_configs if c.get("Id") == "first"), None)
    assert first_entry is not None, f"the first queue config was not returned: {first_configs!r}"
    first_rules = _filter_rules(first_entry)
    assert first_rules == {"prefix": _FIRST_PREFIX, "suffix": _FIRST_SUFFIX}, (
        f"filter rules with reserved/non-ASCII characters did not round-trip exactly: {first_rules!r}"
    )

    s3.put_bucket_notification_configuration(
        Bucket=bucket,
        NotificationConfiguration={
            "QueueConfigurations": [{
                "Id": "second",
                "QueueArn": second_arn,
                "Events": ["s3:ObjectRemoved:*"],
                "Filter": {"Key": {"FilterRules": [
                    {"Name": "prefix", "Value": _SECOND_PREFIX},
                    {"Name": "suffix", "Value": _SECOND_SUFFIX},
                ]}},
            }]
        },
    )
    second_configs = s3.get_bucket_notification_configuration(Bucket=bucket).get("QueueConfigurations", [])
    ids = {c.get("Id") for c in second_configs}
    assert ids == {"second"}, (
        f"the second PutBucketNotificationConfiguration left {ids!r}; expected it to replace "
        "the whole configuration, leaving only 'second'"
    )
    second_entry = second_configs[0]
    assert second_entry["QueueArn"] == second_arn, (
        f"expected the surviving config to point at {second_arn!r}, got {second_entry['QueueArn']!r}"
    )
    second_rules = _filter_rules(second_entry)
    assert second_rules == {"prefix": _SECOND_PREFIX, "suffix": _SECOND_SUFFIX}, (
        f"the second config's filter rules were {second_rules!r}, expected the second set"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
