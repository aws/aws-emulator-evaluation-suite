"""notification-prefix-filter-url-decodes-before-key-matching."""

from __future__ import annotations

import time
import json
import urllib.parse
from typing import Any

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "notification-prefix-filter-url-decodes-before-key-matching"

GROUP = "event-propagation"

SERVICES = ["s3", "sqs"]

# The prefix filter is configured URL-encoded ("%3D" for "="); AWS decodes it to "folder=tag/"
# before matching. A key under the literal encoded text is a different string from a key under
# the decoded prefix, so the two cases are distinguishable.
_ENCODED_PREFIX = "folder%3Dtag/"
_DECODED_PREFIX = "folder=tag/"


@tags(
    "axis:negative-delivery",
    "cap:c1",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A URL-encoded prefix filter decodes before matching object keys: a key under the decoded
    prefix notifies, a key matching only the literal encoded text does not, and
    GetBucketNotificationConfiguration echoes the filter value exactly as configured.
    """
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    bucket = _create_bucket(ctx)
    queue = _create_queue(ctx)

    _set_queue_policy(
        ctx,
        queue["url"],
        _allow_service_send(queue["arn"], "s3.amazonaws.com", bucket["arn"]),
    )

    s3.put_bucket_notification_configuration(
        Bucket=bucket["name"],
        NotificationConfiguration={
            "QueueConfigurations": [
                {
                    "Id": "prefix-filter",
                    "QueueArn": queue["arn"],
                    "Events": ["s3:ObjectCreated:*"],
                    "Filter": {
                        "Key": {
                            "FilterRules": [
                                {"Name": "prefix", "Value": _ENCODED_PREFIX}
                            ]
                        }
                    },
                }
            ]
        },
    )

    # Control-plane read: the filter value comes back exactly as supplied, not decoded.
    config = s3.get_bucket_notification_configuration(Bucket=bucket["name"])
    rules = config["QueueConfigurations"][0]["Filter"]["Key"]["FilterRules"]
    assert rules == [{"Name": "Prefix", "Value": _ENCODED_PREFIX}], (
        f"GetBucketNotificationConfiguration returned FilterRules {rules!r}, expected the "
        f"supplied value {_ENCODED_PREFIX!r} echoed unchanged"
    )

    miss_key = _ENCODED_PREFIX + "literal-encoded-miss.txt"
    hit_key = _DECODED_PREFIX + "decoded-hit.txt"

    # The literal-encoded key is put first so that, if it were wrongly delivered, its notification
    # would arrive before the later hit_key's -- making hit_key's arrival a proof that the drain
    # below did not simply stop too early to see a leaked miss notification.
    s3.put_object(Bucket=bucket["name"], Key=miss_key, Body=b"miss")
    s3.put_object(Bucket=bucket["name"], Key=hit_key, Body=b"hit")

    seen_keys, found_hit = _drain_until_key(ctx, sqs, queue["url"], hit_key, cap_s=180.0)

    assert found_hit, (
        f"expected {hit_key!r} (under the decoded prefix {_DECODED_PREFIX!r}) to notify the "
        f"queue; keys seen while draining: {seen_keys!r}"
    )
    assert miss_key not in seen_keys, (
        f"the literal encoded prefix text {_ENCODED_PREFIX!r} matched key {miss_key!r} and it "
        f"was delivered to the queue, but the filter must match only the url-decoded prefix "
        f"{_DECODED_PREFIX!r}"
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises; only the resource's own not_found
    codes mean it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_queue(ctx) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    name = _xname(ctx, "q")
    sqs = ctx.client("sqs")
    resp = sqs.create_queue(QueueName=name, tags=_xsvc_resource_tags())
    url = resp["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    ctx.on_cleanup(
        _teardown(
            lambda: sqs.delete_queue(QueueUrl=url),
            "AWS.SimpleQueueService.NonExistentQueue",
        )
    )
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


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    """Purge every object (delete_bucket refuses a non-empty bucket with BucketNotEmpty), then
    delete the bucket."""
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            targets = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if targets:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": targets})
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchBucket":
            return
        raise
    s3.delete_bucket(Bucket=bucket)


def _allow_service_send(queue_arn: str, service: str, source_arn: str) -> dict:
    """A queue policy granting one AWS service SendMessage on this queue, scoped by SourceArn."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowServiceSend",
                "Effect": "Allow",
                "Principal": {"Service": service},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": source_arn}},
            }
        ],
    }


def _set_queue_policy(ctx, queue_url: str, policy: dict) -> None:
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)}
    )


def _record_keys(msg: dict) -> list:
    """Object keys carried by a notification message's Records, URL-decoded back to the literal
    key a customer wrote (the Records field itself is URL-encoded); [] for a message with none
    (s3:TestEvent, or a body that failed to parse as JSON)."""
    raw = msg.get("Body", "")
    try:
        body = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(body, dict):
        return []
    keys = []
    for r in body.get("Records", []):
        key = r.get("s3", {}).get("object", {}).get("key")
        if key is not None:
            key = urllib.parse.unquote(key)
        keys.append(key)
    return keys


def _drain_until_key(ctx, sqs, queue_url: str, target_key: str, *, cap_s: float = 180.0):
    """Drain queue_url, collecting every record key seen, until target_key arrives or the
    deadline elapses. The deadline is cap_s, bounded by the runner's own remaining time so a
    stuck drain fails with its own message rather than as a runner timeout.

    Returns (keys_seen, found) -- keys_seen holds every record key observed along the way, so a
    delivery of a key other than target_key is never silently discarded.
    """
    left = ctx.time_left()
    budget = cap_s if left is None else max(1.0, min(cap_s, left - 10.0))
    deadline = time.monotonic() + budget
    keys: list = []
    found = False
    while time.monotonic() < deadline and not found:
        wait = min(5, max(1, int(deadline - time.monotonic())))
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            for key in _record_keys(msg):
                keys.append(key)
                if key == target_key:
                    found = True
    return keys, found


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
