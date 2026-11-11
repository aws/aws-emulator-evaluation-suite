"""s3-notification-filter-prefix-positive."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-notification-filter-prefix-positive"

GROUP = "data-format"

SERVICES = ["cloudformation", "lambda", "s3", "sqs"]


def _msg_body_json(msg: dict) -> dict:
    """Return message body as a parsed dict, whether harness returns str or dict."""
    raw = msg.get("Body") or msg.get("body", "{}")
    if isinstance(raw, dict):
        return raw
    return json.loads(raw)


def _drain_s3_test_events(sqs_client, queue_url: str, timeout_s: int = 15) -> None:
    """Drain S3 TestEvent messages that AWS sends when configuring bucket notifications.

    When a bucket notification is configured, S3 sends a 's3:TestEvent' to each destination.
    This helper drains those probe messages so checks only see real object events.
    """

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs_client.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=2,
        )
        msgs = resp.get("Messages", [])
        if not msgs:
            break
        for msg in msgs:
            raw = _msg_body_json(msg)
            # If it is a test event, delete it; otherwise leave it (shouldn't happen pre-PutObject)
            if raw.get("Event") == "s3:TestEvent" or raw.get("Service") == "Amazon S3":
                sqs_client.delete_message(
                    QueueUrl=queue_url,
                    ReceiptHandle=msg["ReceiptHandle"],
                )


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """S3 notification with KeyPrefixEquals filter only delivers matching prefix events."""
    queue = _create_queue(ctx)
    bucket = _create_bucket(ctx)

    sqs = ctx.client("sqs")
    queue_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "s3.amazonaws.com"},
                    "Action": "sqs:SendMessage",
                    "Resource": queue["arn"],
                }
            ],
        }
    )
    sqs.set_queue_attributes(
        QueueUrl=queue["url"],
        Attributes={"Policy": queue_policy},
    )

    s3 = ctx.client("s3")
    s3.put_bucket_notification_configuration(
        Bucket=bucket["name"],
        NotificationConfiguration={
            "QueueConfigurations": [
                {
                    "QueueArn": queue["arn"],
                    "Events": ["s3:ObjectCreated:*"],
                    "Filter": {
                        "Key": {"FilterRules": [{"Name": "prefix", "Value": "events/"}]}
                    },
                }
            ]
        },
    )

    # Drain S3 test events that arrive when the notification config is set
    sqs_drain = ctx.client("sqs")
    _drain_s3_test_events(sqs_drain, queue["url"])

    # Upload matching key first
    put_t0 = time.monotonic()
    s3.put_object(Bucket=bucket["name"], Key="events/match.txt", Body=b"match")
    # Upload non-matching key
    s3.put_object(Bucket=bucket["name"], Key="other/nomatch.txt", Body=b"nomatch")

    messages = _wait_for_messages(ctx, queue["url"], expected_count=1, timeout_s=60)
    positive_latency_s = time.monotonic() - put_t0
    assert messages, "No notification for matching prefix"
    # Check that only the matching key notification arrived
    body = _msg_body_json(messages[0])
    records = body.get("Records", [])
    assert records, f"No records: {body}"
    key = records[0]["s3"]["object"]["key"]
    assert key == "events/match.txt", f"Expected events/match.txt, got: {key}"

    # Verify no notification for the non-matching key ever arrives. The window is calibrated to
    # the delivery latency actually observed above on this same wiring, not a fixed short wait:
    # a window shorter than the positive control's own latency would score a correct-but-slower
    # target as having blocked the non-matching key by construction.
    sqs_client = ctx.client("sqs")
    absence_window_s = max(3 * positive_latency_s, 15.0)
    deadline = time.monotonic() + absence_window_s
    while time.monotonic() < deadline:
        remaining = max(1, int(deadline - time.monotonic()))
        resp = sqs_client.receive_message(
            QueueUrl=queue["url"],
            MaxNumberOfMessages=10,
            WaitTimeSeconds=min(20, remaining),
        )
        for msg in resp.get("Messages", []):
            extra_body = _msg_body_json(msg)
            extra_records = extra_body.get("Records", [])
            for r in extra_records:
                assert r["s3"]["object"]["key"] != "other/nomatch.txt", (
                    "Non-matching key 'other/nomatch.txt' produced a notification within "
                    f"{absence_window_s:.1f}s: prefix filter 'events/' failed to exclude it"
                )
            sqs_client.delete_message(QueueUrl=queue["url"], ReceiptHandle=msg["ReceiptHandle"])

    # Second independent observable: the queue's own reported depth agrees nothing is left to
    # deliver, not just that this check's polling happened not to see anything.
    attrs_deadline = time.monotonic() + 30.0
    approx_depth = None
    while time.monotonic() < attrs_deadline:
        approx_depth = sqs_client.get_queue_attributes(
            QueueUrl=queue["url"], AttributeNames=["ApproximateNumberOfMessages"]
        )["Attributes"]["ApproximateNumberOfMessages"]
        if approx_depth == "0":
            break
        time.sleep(2)
    assert approx_depth == "0", (
        f"Queue reports {approx_depth} message(s) still pending after draining for "
        f"{absence_window_s:.1f}s"
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


def _wait_for_messages(ctx, queue_url, expected_count=1, timeout_s=60.0, delete=True):
    """Poll SQS until expected_count messages arrive; return them (raises on timeout)."""
    sqs = ctx.client("sqs")
    messages: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while len(messages) < expected_count and time.monotonic() < deadline:
        remaining = max(1, int(deadline - time.monotonic()))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=min(10, expected_count - len(messages)),
            WaitTimeSeconds=min(5, remaining),
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            messages.append(
                {
                    "body": body,
                    "message_id": msg["MessageId"],
                    "receipt_handle": msg["ReceiptHandle"],
                    "attributes": msg.get("MessageAttributes", {}),
                }
            )
            if delete:
                sqs.delete_message(
                    QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"]
                )
    if len(messages) < expected_count:
        raise AssertionError(
            f"Expected {expected_count} messages, got {len(messages)} within {timeout_s}s"
        )
    return messages


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
