"""s3-object-created-put-subscription-withholds-the-multipart-completion-event."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-object-created-put-subscription-withholds-the-multipart-completion-event"
GROUP = "event-propagation"
SERVICES = ["s3", "sqs"]

_PREFIX = "mpu/"
_PART = b"M" * (5 * 1024 * 1024)
_NPARTS = 2
_HOLD_CAP_S = 180.0


@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two queues on one prefix subscribed to ObjectCreated:Put and CompleteMultipartUpload each get
    only their event: the multipart completion (with the assembled size and ETag) reaches only its
    queue, while the Put queue stays empty for max(3L, 15s) and still delivers a later PutObject.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-how-to-event-types-and-destinations.html
    """
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    bucket = _create_bucket(ctx)
    q_put = _create_queue(ctx)
    q_mpu = _create_queue(ctx)

    for q in (q_put, q_mpu):
        _set_queue_policy(
            ctx, q["url"], _allow_service_send(q["arn"], "s3.amazonaws.com", bucket["arn"])
        )

    s3.put_bucket_notification_configuration(
        Bucket=bucket["name"],
        NotificationConfiguration={
            "QueueConfigurations": [
                {
                    "Id": "put-only",
                    "QueueArn": q_put["arn"],
                    "Events": ["s3:ObjectCreated:Put"],
                    "Filter": {"Key": {"FilterRules": [{"Name": "prefix", "Value": _PREFIX}]}},
                },
                {
                    "Id": "mpu-only",
                    "QueueArn": q_mpu["arn"],
                    "Events": ["s3:ObjectCreated:CompleteMultipartUpload"],
                    "Filter": {"Key": {"FilterRules": [{"Name": "prefix", "Value": _PREFIX}]}},
                },
            ]
        },
    )
    got = s3.get_bucket_notification_configuration(Bucket=bucket["name"])
    events = {c["Id"]: c["Events"] for c in got.get("QueueConfigurations", [])}
    assert events == {
        "put-only": ["s3:ObjectCreated:Put"],
        "mpu-only": ["s3:ObjectCreated:CompleteMultipartUpload"],
    }, (
        f"GetBucketNotificationConfiguration reports {events!r}; expected the two disjoint "
        "single-event subscriptions this check installed"
    )

    # S3 validates each new destination by sending it one s3:TestEvent.
    for label, q in (("put-only", q_put), ("mpu-only", q_mpu)):
        test_events, others = _wait_for(
            ctx, q["url"],
            lambda b: isinstance(b, dict) and b.get("Event") == "s3:TestEvent",
            timeout_s=60.0,
        )
        assert test_events, (
            f"the {label} destination received no s3:TestEvent when the notification configuration "
            f"was installed; it saw {[_body(m) for m in others][:2]!r}"
        )

    # Control: a plain PutObject reaches the Put-only queue, and L is its measured latency.
    plain_key = f"{_PREFIX}plain.txt"
    started = time.monotonic()
    s3.put_object(Bucket=bucket["name"], Key=plain_key, Body=b"plain-single-part-write")
    matched, others = _wait_for(
        ctx, q_put["url"], lambda b: _has_record(b, plain_key), timeout_s=120.0
    )
    assert matched, (
        f"control: PutObject {plain_key!r} produced no notification on the s3:ObjectCreated:Put "
        f"destination within 120s; non-matching traffic seen: {[_body(m) for m in others][:2]!r}"
    )
    put_latency_s = time.monotonic() - started
    record = _record(_body(matched[0]), plain_key)
    assert record["eventName"] == "ObjectCreated:Put", (
        f"the PutObject notification carries eventName {record['eventName']!r}, expected "
        "'ObjectCreated:Put'"
    )

    mpu_key = f"{_PREFIX}assembled.bin"
    upload = s3.create_multipart_upload(Bucket=bucket["name"], Key=mpu_key)
    parts = []
    for number in range(1, _NPARTS + 1):
        uploaded = s3.upload_part(
            Bucket=bucket["name"], Key=mpu_key, UploadId=upload["UploadId"],
            PartNumber=number, Body=_PART,
        )
        parts.append({"PartNumber": number, "ETag": uploaded["ETag"]})
    mpu_started = time.monotonic()
    s3.complete_multipart_upload(
        Bucket=bucket["name"], Key=mpu_key, UploadId=upload["UploadId"],
        MultipartUpload={"Parts": parts},
    )
    head = s3.head_object(Bucket=bucket["name"], Key=mpu_key)
    expected_etag = head["ETag"].strip('"')
    expected_size = head["ContentLength"]
    assert expected_size == _NPARTS * len(_PART), (
        f"the assembled object is {expected_size} bytes, expected {_NPARTS * len(_PART)}"
    )

    matched, others = _wait_for(
        ctx, q_mpu["url"], lambda b: _has_record(b, mpu_key), timeout_s=120.0
    )
    assert matched, (
        f"CompleteMultipartUpload on {mpu_key!r} produced no notification on the "
        f"s3:ObjectCreated:CompleteMultipartUpload destination within 120s; traffic seen: "
        f"{[_body(m) for m in others][:2]!r}"
    )
    mpu_latency_s = time.monotonic() - mpu_started
    record = _record(_body(matched[0]), mpu_key)
    assert record["eventName"] == "ObjectCreated:CompleteMultipartUpload", (
        f"the multipart completion notification carries eventName {record['eventName']!r}, expected "
        "'ObjectCreated:CompleteMultipartUpload' — the four ObjectCreated sub-types are being "
        "collapsed into one"
    )
    assert record["s3"]["object"]["size"] == expected_size, (
        f"the notification reports size {record['s3']['object'].get('size')!r}; HeadObject reports "
        f"{expected_size} for the same object"
    )
    assert record["s3"]["object"]["eTag"] == expected_etag, (
        f"the notification reports eTag {record['s3']['object'].get('eTag')!r}; HeadObject reports "
        f"{expected_etag!r} (part-count-suffixed, unquoted) for the same object"
    )

    hold_s = min(max(3.0 * max(put_latency_s, mpu_latency_s), 15.0), _HOLD_CAP_S)
    leaked = _collect(ctx, q_put["url"], window_s=hold_s)
    leaked_keys = [
        r.get("s3", {}).get("object", {}).get("key")
        for m in leaked
        if isinstance(_body(m), dict)
        for r in _body(m).get("Records", [])
    ]
    assert leaked_keys == [], (
        f"the s3:ObjectCreated:Put destination received notification(s) for {leaked_keys} within "
        f"{hold_s:.0f}s — a multipart completion is not an ObjectCreated:Put, and the multipart "
        f"event itself arrived on the other queue in {mpu_latency_s:.1f}s, so a leaked copy would "
        "have arrived by now"
    )
    # second observable: the Put queue's visible counter polls to 0 after the empty long-poll
    _poll_queue_counters(ctx, sqs, q_put["url"], {"ApproximateNumberOfMessages": "0"})

    # Re-prove delivery, so the empty window cannot mean the destination went quiet.
    second_key = f"{_PREFIX}plain-again.txt"
    s3.put_object(Bucket=bucket["name"], Key=second_key, Body=b"second-single-part-write")
    matched, _ = _wait_for(
        ctx, q_put["url"], lambda b: _has_record(b, second_key), timeout_s=120.0
    )
    assert matched, (
        f"a second PutObject {second_key!r} produced no notification on the Put destination — "
        "without this the empty window above would only mean the destination had gone quiet"
    )
    assert _record(_body(matched[0]), second_key)["eventName"] == "ObjectCreated:Put", (
        "the second PutObject's notification does not carry eventName 'ObjectCreated:Put'"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict:
    return {_MANAGED_TAG_KEY: "true", "sim2real:check": CHECK}


def _xsvc_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _create_queue(ctx) -> dict:
    """Create a tagged SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    name = _xname(ctx, "q")
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=name, tags=_xsvc_resource_tags())["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"name": name, "url": url, "arn": arn}


def _body(msg: dict):
    """Parse an SQS message body as JSON, falling back to the raw string."""
    raw = msg.get("Body", "")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw


def _has_record(body, key: str) -> bool:
    """True when a parsed notification body carries a Records entry for `key`."""
    return isinstance(body, dict) and any(
        r.get("s3", {}).get("object", {}).get("key") == key for r in body.get("Records", [])
    )


def _record(body, key: str) -> dict:
    """The single Records entry for `key`. Hard-fails rather than defaulting."""
    matches = [
        r for r in body.get("Records", []) if r.get("s3", {}).get("object", {}).get("key") == key
    ]
    assert len(matches) == 1, (
        f"expected exactly one notification record for {key!r}, found {len(matches)} in {body!r}"
    )
    return matches[0]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_queue_counters(ctx, sqs, queue_url, expected, cap_s=90.0):
    """Poll GetQueueAttributes until every named counter equals its expected string value.

    The ApproximateNumberOf* counters may lag up to a minute after producers stop
    (SQS GetQueueAttributes docs), so a single read is not a verdict."""
    budget_s = _budget_s(ctx, cap_s)
    start = time.monotonic()
    stop = start + min(cap_s, budget_s)
    while True:
        attrs = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=list(expected))["Attributes"]
        observed = {name: attrs.get(name) for name in expected}
        if observed == expected:
            return attrs
        if time.monotonic() >= stop:
            if budget_s < cap_s:
                raise TimeoutError(
                    f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
                    f"{cap_s}s counter wait ended (last observed {observed}); not graded"
                )
            raise AssertionError(f"queue counters never reached {expected}; last observed {observed}")
        time.sleep(3)


def _collect(ctx, queue_url, *, window_s=30.0, max_total=20):
    """Drain a queue over a bounded window with long-polling receives; return every message seen."""
    sqs = ctx.client("sqs")
    seen: list = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline and len(seen) < max_total:
        wait = min(5, max(1, int(deadline - time.monotonic())))
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait
        )
        for msg in resp.get("Messages", []):
            seen.append(msg)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return seen


def _wait_for(ctx, queue_url, predicate, *, timeout_s=60.0):
    """Poll a queue until a message whose parsed body satisfies predicate() arrives.

    Returns (matched, others); matched is empty on timeout."""
    matched: list = []
    others: list = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and not matched:
        for msg in _collect(ctx, queue_url, window_s=min(2.0, timeout_s)):
            (matched if predicate(_body(msg)) else others).append(msg)
    return matched, others


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


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    """Teardown: abort open multipart uploads, purge every version and delete marker, delete the
    bucket."""
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
            for upload in page.get("Uploads", []):
                try:
                    s3.abort_multipart_upload(
                        Bucket=bucket, Key=upload["Key"], UploadId=upload["UploadId"]
                    )
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "NoSuchUpload":
                        raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchBucket":
            return
        raise
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            targets = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if targets:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": targets}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchBucket":
            return
        raise
    s3.delete_bucket(Bucket=bucket)


def _create_bucket(ctx) -> dict:
    """Create a tagged S3 bucket (registers empty-then-delete teardown). Returns {name,arn}."""
    name = _xname(ctx, "bkt")
    s3 = ctx.client("s3")
    kwargs: dict = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})
    return {"name": name, "arn": f"arn:aws:s3:::{name}"}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
