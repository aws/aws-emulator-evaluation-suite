"""s3-multi-event-type-routing-sqs."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-multi-event-type-routing-sqs"

GROUP = "event-propagation"

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


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An S3 notification configuration delivers ObjectCreated only to its queue and ObjectRemoved only
    to its own, with nothing leaking to the other queue in either direction."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    created_queue = _create_queue(ctx)
    removed_queue = _create_queue(ctx)

    _set_queue_policy(
        ctx,
        created_queue["url"],
        _sqs_policy_for_s3(created_queue["arn"], bucket["arn"]),
    )
    _set_queue_policy(
        ctx,
        removed_queue["url"],
        _sqs_policy_for_s3(removed_queue["arn"], bucket["arn"]),
    )

    s3.put_bucket_notification_configuration(
        Bucket=bucket["name"],
        NotificationConfiguration={
            "QueueConfigurations": [
                {
                    "QueueArn": created_queue["arn"],
                    "Events": ["s3:ObjectCreated:*"],
                    "Id": "created",
                },
                {
                    "QueueArn": removed_queue["arn"],
                    "Events": ["s3:ObjectRemoved:*"],
                    "Id": "removed",
                },
            ]
        },
    )

    # Control 1: ObjectCreated must land on created_queue, and must not leak to removed_queue.
    s3.put_object(Bucket=bucket["name"], Key="route-me.txt", Body=b"x")
    created_msgs = _wait_for_s3_records(
        ctx, created_queue["url"], expected_count=1, timeout_s=90
    )
    created_event_name = created_msgs[0]["body"]["Records"][0]["eventName"]
    assert created_event_name.startswith("ObjectCreated"), (
        f"expected an ObjectCreated* eventName on created_queue, got {created_event_name!r}"
    )
    leaked_to_removed = _real_event_names(_drain(ctx, removed_queue["url"], window_s=45))
    assert leaked_to_removed == [], (
        "ObjectCreated notification leaked to removed_queue -- routing is not isolated per "
        f"destination, got {leaked_to_removed}"
    )

    # Control 2: ObjectRemoved must land on removed_queue, and must not leak to created_queue.
    s3.delete_object(Bucket=bucket["name"], Key="route-me.txt")
    removed_msgs = _wait_for_s3_records(
        ctx, removed_queue["url"], expected_count=1, timeout_s=90
    )
    removed_event_name = removed_msgs[0]["body"]["Records"][0]["eventName"]
    assert removed_event_name.startswith("ObjectRemoved"), (
        f"expected an ObjectRemoved* eventName on removed_queue, got {removed_event_name!r}"
    )
    leaked_to_created = _real_event_names(_drain(ctx, created_queue["url"], window_s=45))
    assert leaked_to_created == [], (
        "ObjectRemoved notification leaked to created_queue -- routing is not isolated per "
        f"destination, got {leaked_to_created}"
    )


def _drain(ctx, queue_url: str, *, window_s: float = 45.0, max_total: int = 10) -> list[dict]:
    """Drain a queue over a bounded window, deleting every message seen, and return them all.

    This is the negative half of a routing-isolation check: meaningful only once a positive
    control has already been observed on the same wiring in this run, since an empty return alone
    cannot distinguish 'correctly isolated' from 'nothing is wired at all'."""
    sqs = ctx.client("sqs")
    seen: list[dict] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline and len(seen) < max_total:
        wait = min(5, max(1, int(deadline - time.monotonic())))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=wait,
            MessageAttributeNames=["All"],
        )
        for m in resp.get("Messages", []):
            seen.append(m)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return seen


def _real_event_names(msgs: list[dict]) -> list[str]:
    """eventName of every real (non s3:TestEvent) S3 record among raw SQS messages."""
    out: list[str] = []
    for m in msgs:
        try:
            body = json.loads(m["Body"])
        except (json.JSONDecodeError, ValueError):
            continue
        if _is_s3_test_event(body) or not isinstance(body, dict):
            continue
        for r in body.get("Records", []):
            out.append(r.get("eventName"))
    return out


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
    """S3 refuses to delete a non-empty bucket (BucketNotEmpty), so purge objects AND all
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
