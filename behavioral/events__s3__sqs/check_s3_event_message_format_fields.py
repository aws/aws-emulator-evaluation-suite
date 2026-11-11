"""s3-event-message-format-fields."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-event-message-format-fields"

GROUP = "data-format"

SERVICES = ["events", "s3", "sqs"]


def _is_s3_test_event(body: object) -> bool:
    """True for S3's one-off destination-validation handshake message.

    When a queue is first attached as an S3 notification destination, S3 posts
    {"Service":"Amazon S3","Event":"s3:TestEvent", ...} to prove it can write to
    the queue. It carries no "Records" and is NOT an object event, so it must
    never be mistaken for one (nor counted as an over-delivery).
    """
    return isinstance(body, dict) and body.get("Event") == "s3:TestEvent"


def _wait_for_s3_records(
    ctx,
    queue_url: str,
    expected_count: int = 1,
    timeout_s: float = 90,
) -> list[dict]:
    """Poll SQS for real S3 object-event notifications, discarding s3:TestEvent."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    out: list[dict] = []
    while len(out) < expected_count and time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=5,
            MessageAttributeNames=["All"],
        )
        for m in resp.get("Messages", []):
            try:
                body = json.loads(m["Body"])
            except (json.JSONDecodeError, ValueError):
                body = m["Body"]
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if _is_s3_test_event(body):
                continue
            out.append({"body": body, "attributes": m.get("MessageAttributes", {})})
    if len(out) < expected_count:
        raise AssertionError(
            f"expected {expected_count} S3 notification(s), got {len(out)} within {timeout_s}s"
        )
    return out


def _sqs_policy_for_s3(queue_arn: str, bucket_arn: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3SendMessage",
                "Effect": "Allow",
                "Principal": {"Service": "s3.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": bucket_arn}},
            }
        ],
    }


def _set_queue_policy(ctx, queue_url: str, policy: dict) -> None:
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)}
    )


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """S3 event notification records carry eventName, eventTime, awsRegion, size, eTag (MD5 of
    the body) and the bucket ARN, all matching the PutObject call that triggered them."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    queue = _create_queue(ctx)

    _set_queue_policy(
        ctx, queue["url"], _sqs_policy_for_s3(queue["arn"], bucket["arn"])
    )
    s3.put_bucket_notification_configuration(
        Bucket=bucket["name"],
        NotificationConfiguration={
            "QueueConfigurations": [
                {"QueueArn": queue["arn"], "Events": ["s3:ObjectCreated:Put"]}
            ]
        },
    )

    body_bytes = b"0123456789"
    before_put = dt.datetime.now(dt.timezone.utc)
    s3.put_object(Bucket=bucket["name"], Key="format-check.bin", Body=body_bytes)
    expected_etag = hashlib.md5(body_bytes).hexdigest()

    messages = _wait_for_s3_records(ctx, queue["url"], expected_count=1, timeout_s=90)
    assert messages, "expected S3 notification for format check"
    record = messages[0]["body"]["Records"][0]

    assert record["eventName"] == "ObjectCreated:Put", (
        f"expected eventName 'ObjectCreated:Put', got {record.get('eventName')!r}"
    )
    assert record["eventSource"] == "aws:s3", (
        f"expected eventSource 'aws:s3', got {record.get('eventSource')!r}"
    )
    event_time = dt.datetime.strptime(record["eventTime"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(
        tzinfo=dt.timezone.utc
    )
    now = dt.datetime.now(dt.timezone.utc)
    assert before_put - dt.timedelta(minutes=1) <= event_time <= now + dt.timedelta(minutes=1), (
        f"eventTime {record['eventTime']!r} is not within a minute of the PutObject call "
        f"(issued at {before_put.isoformat()}, observed at {now.isoformat()})"
    )
    assert record.get("awsRegion") == ctx.region, (
        f"expected awsRegion {ctx.region!r}, got {record.get('awsRegion')!r}"
    )
    s3_data = record["s3"]
    assert s3_data["bucket"]["name"] == bucket["name"], (
        f"expected bucket name {bucket['name']!r}, got {s3_data['bucket'].get('name')!r}"
    )
    assert s3_data["bucket"]["arn"] == bucket["arn"], (
        f"expected bucket arn {bucket['arn']!r}, got {s3_data['bucket'].get('arn')!r}"
    )
    assert s3_data["object"]["key"] == "format-check.bin", (
        f"expected object key 'format-check.bin', got {s3_data['object'].get('key')!r}"
    )
    assert int(s3_data["object"]["size"]) == len(body_bytes), (
        f"expected object size {len(body_bytes)}, got {s3_data['object'].get('size')!r}"
    )
    assert s3_data["object"]["eTag"] == expected_etag, (
        f"expected eTag {expected_etag!r} (MD5 of the {len(body_bytes)}-byte body), "
        f"got {s3_data['object'].get('eTag')!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    """S3 buckets must be emptied before deletion — a raw delete_bucket on a non-empty bucket fails
    with BucketNotEmpty and (since teardown swallows errors) leaks the bucket. Purge objects AND all
    versions/delete-markers (versioning may be on), then delete."""
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            targets = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if targets:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": targets}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError:
        try:
            p2 = s3.get_paginator("list_objects_v2")
            for page in p2.paginate(Bucket=bucket):
                keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
                if keys:
                    failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
                    if failed:
                        raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
    s3.delete_bucket(Bucket=bucket)


def _create_queue(ctx, fifo: bool = False, **attrs: str) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    base = _xname(ctx, "q")
    name = f"{base}.fifo" if fifo else base
    sqs = ctx.client("sqs")
    create_attrs = dict(attrs)
    if fifo:
        create_attrs["FifoQueue"] = "true"
    resp = sqs.create_queue(
        QueueName=name, Attributes=create_attrs, tags=_xsvc_resource_tags()
    )
    url = resp["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"name": name, "url": url, "arn": arn}


def _create_bucket(ctx) -> dict[str, str]:
    """Create an S3 bucket (registers empty-then-delete teardown). Returns {name,arn}."""
    name = _xname(ctx, "bkt")
    s3 = ctx.client("s3")
    create_kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    try:
        s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})
    except ClientError:
        pass
    return {"name": name, "arn": f"arn:aws:s3:::{name}"}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
