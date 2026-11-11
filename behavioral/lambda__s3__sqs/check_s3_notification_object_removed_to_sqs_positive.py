"""s3-notification-object-removed-to-sqs-positive."""
from __future__ import annotations

import json
import time
from typing import Any

import botocore.exceptions

from behavioral_harness import tags

CHECK = "s3-notification-object-removed-to-sqs-positive"
GROUP = "event-propagation"
SERVICES = ["lambda", "s3", "sqs"]
_TAG_KEY = "sim2real:check"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An ObjectRemoved:Delete notification delivers a message to the configured SQS
    queue with the correct bucket/key details of the deleted object."""
    s3 = ctx.client("s3")
    bucket_name = _create_bucket(ctx)
    queue_url, queue_arn = _create_queue(ctx)
    _set_queue_policy_for_s3(ctx, queue_url, queue_arn, bucket_name)

    s3.put_bucket_notification_configuration(
        Bucket=bucket_name,
        NotificationConfiguration={
            "QueueConfigurations": [
                {"QueueArn": queue_arn, "Events": ["s3:ObjectRemoved:Delete"]}
            ]
        },
    )

    key = "objects/removed-item.txt"
    s3.put_object(Bucket=bucket_name, Key=key, Body=b"to-be-deleted")
    s3.delete_object(Bucket=bucket_name, Key=key)

    # A HEAD response carries no body, so S3 returns no error message to assert.
    gone_code, _ = _expect_error(lambda: s3.head_object(Bucket=bucket_name, Key=key))
    assert gone_code == "404", f"expected deleted object gone (404), got code={gone_code!r}"

    records = _poll_for_records(ctx, queue_url, timeout_s=90.0)
    matches = [r for r in records if r["s3"]["object"]["key"] == key]
    assert matches, f"no SQS-delivered record for key {key} in {records}"
    record = matches[0]
    assert record["eventName"] == "ObjectRemoved:Delete", (
        f"expected eventName 'ObjectRemoved:Delete', got {record['eventName']!r}"
    )
    assert record["s3"]["bucket"]["name"] == bucket_name, (
        f"expected bucket {bucket_name!r} in notification, got {record['s3']['bucket']['name']!r}"
    )


def _expect_error(fn):
    """Call fn(); return the botocore Error (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except botocore.exceptions.ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _wait_for_effect(
    probe, predicate, timeout_s=120.0, interval_s=2.0, description="effect"
):
    return _poll_until(
        probe,
        predicate,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=description,
    )


def _create_bucket(ctx, versioned: bool = False) -> str:
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-s3sqs-bkt-")
    kwargs: dict[str, Any] = {"Bucket": bucket_name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": _TAG_KEY, "Value": CHECK}]}
    )

    def _cleanup():
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket_name):
            objs = [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("Versions", [])
            ]
            objs += [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("DeleteMarkers", [])
            ]
            if objs:
                failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket_name)

    ctx.on_cleanup(_cleanup)
    if versioned:
        s3.put_bucket_versioning(
            Bucket=bucket_name, VersioningConfiguration={"Status": "Enabled"}
        )
    return bucket_name


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    queue_name = ctx.unique_name("sim2real-s3sqs-q-")
    queue_url = sqs.create_queue(
        QueueName=queue_name, tags={_TAG_KEY: CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]
    return queue_url, queue_arn


def _set_queue_policy_for_s3(ctx, queue_url: str, queue_arn: str, bucket_name: str):
    sqs = ctx.client("sqs")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3Notify",
                "Effect": "Allow",
                "Principal": {"Service": "s3.amazonaws.com"},
                "Action": "SQS:SendMessage",
                "Resource": queue_arn,
                "Condition": {
                    "ArnEquals": {"aws:SourceArn": f"arn:aws:s3:::{bucket_name}"}
                },
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})


def _poll_for_records(ctx, queue_url: str, timeout_s: float = 90.0) -> list[dict[str, Any]]:
    sqs = ctx.client("sqs")
    collected: list[dict[str, Any]] = []

    def probe():
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            for rec in body.get("Records", []):
                collected.append(rec)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        return collected

    _wait_for_effect(
        probe,
        lambda recs: len(recs) > 0,
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"S3 event delivered to queue {queue_url}",
    )
    return collected


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
