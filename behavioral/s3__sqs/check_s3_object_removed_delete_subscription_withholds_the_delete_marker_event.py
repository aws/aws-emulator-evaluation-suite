"""s3-object-removed-delete-subscription-withholds-the-delete-marker-event."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-object-removed-delete-subscription-withholds-the-delete-marker-event"
GROUP = "event-propagation"
SERVICES = ["s3", "sqs"]

_PREFIX = "v/"
_KEY = f"{_PREFIX}subject.bin"
_BODY = b"versioned-removal-payload"
_HOLD_CAP_S = 180.0


@tags(
    "axis:negative-delivery",
    "cap:c2",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """On a versioned bucket, a delete marker reaches only the ObjectRemoved:DeleteMarkerCreated queue
    and a permanent version delete only the ObjectRemoved:Delete queue, each carrying its versionId and
    no size; each queue stays quiet for the other's event, and ListObjectVersions agrees.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-how-to-event-types-and-destinations.html
    """
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    bucket = _create_versioned_bucket(ctx)
    q_delete = _create_queue(ctx)
    q_marker = _create_queue(ctx)

    for q in (q_delete, q_marker):
        _set_queue_policy(
            ctx, q["url"], _allow_service_send(q["arn"], "s3.amazonaws.com", bucket["arn"])
        )

    s3.put_bucket_notification_configuration(
        Bucket=bucket["name"],
        NotificationConfiguration={
            "QueueConfigurations": [
                {
                    "Id": "permanent-delete-only",
                    "QueueArn": q_delete["arn"],
                    "Events": ["s3:ObjectRemoved:Delete"],
                    "Filter": {"Key": {"FilterRules": [{"Name": "prefix", "Value": _PREFIX}]}},
                },
                {
                    "Id": "delete-marker-only",
                    "QueueArn": q_marker["arn"],
                    "Events": ["s3:ObjectRemoved:DeleteMarkerCreated"],
                    "Filter": {"Key": {"FilterRules": [{"Name": "prefix", "Value": _PREFIX}]}},
                },
            ]
        },
    )
    got = s3.get_bucket_notification_configuration(Bucket=bucket["name"])
    events = {c["Id"]: c["Events"] for c in got.get("QueueConfigurations", [])}
    assert events == {
        "permanent-delete-only": ["s3:ObjectRemoved:Delete"],
        "delete-marker-only": ["s3:ObjectRemoved:DeleteMarkerCreated"],
    }, (
        f"GetBucketNotificationConfiguration reports {events!r}; expected the two disjoint "
        "single-event removal subscriptions this check installed"
    )

    # Drain the configuration-time s3:TestEvent from both queues so the queue-depth observable below
    # measures only notification traffic; each drain ends once its queue's TestEvent arrives.
    for q in (q_delete, q_marker):
        _wait_for(
            ctx, q["url"], lambda b: isinstance(b, dict) and b.get("Event") == "s3:TestEvent",
            timeout_s=30.0,
        )

    version_id = s3.put_object(Bucket=bucket["name"], Key=_KEY, Body=_BODY)["VersionId"]
    assert version_id and version_id != "null", (
        f"PutObject into a versioning-enabled bucket returned VersionId {version_id!r}"
    )

    # --- Leg 1: a version-less delete creates a marker, which reaches ONLY the marker queue.
    started = time.monotonic()
    marker = s3.delete_object(Bucket=bucket["name"], Key=_KEY)
    assert marker.get("DeleteMarker") is True, (
        f"DeleteObject without a VersionId returned DeleteMarker {marker.get('DeleteMarker')!r}, "
        "expected True"
    )
    marker_version = marker["VersionId"]
    matched, others = _wait_for(
        ctx, q_marker["url"], lambda b: _has_record(b, _KEY), timeout_s=120.0
    )
    assert matched, (
        f"the delete marker on {_KEY!r} produced no notification on the "
        f"s3:ObjectRemoved:DeleteMarkerCreated destination within 120s; traffic seen: "
        f"{[_body(m) for m in others][:2]!r}"
    )
    marker_latency_s = time.monotonic() - started
    record = _record(_body(matched[0]), _KEY)
    assert record["eventName"] == "ObjectRemoved:DeleteMarkerCreated", (
        f"the delete-marker notification carries eventName {record['eventName']!r}, expected "
        "'ObjectRemoved:DeleteMarkerCreated'"
    )
    assert record["s3"]["object"]["versionId"] == marker_version, (
        f"the notification reports versionId {record['s3']['object'].get('versionId')!r}; the "
        f"DeleteObject response returned the marker id {marker_version!r}"
    )
    assert "size" not in record["s3"]["object"], (
        f"the delete-marker notification carries an object size "
        f"{record['s3']['object'].get('size')!r}; a removal record has no size"
    )

    hold_s = min(max(3.0 * marker_latency_s, 15.0), _HOLD_CAP_S)
    _assert_quiet(
        ctx, sqs, q_delete,
        hold_s=hold_s,
        reason=(
            f"a delete marker is not a permanent delete, and the marker event reached the other "
            f"queue in {marker_latency_s:.1f}s, so a leaked copy would have arrived by now"
        ),
    )

    # --- Leg 2: a version-qualified delete reaches ONLY the permanent-delete queue. This both
    # re-proves the Delete queue was live during leg 1's window and controls leg 2's own absence.
    started = time.monotonic()
    permanent = s3.delete_object(Bucket=bucket["name"], Key=_KEY, VersionId=version_id)
    assert permanent.get("DeleteMarker") is not True, (
        f"deleting version {version_id} reported DeleteMarker "
        f"{permanent.get('DeleteMarker')!r}; a version-qualified delete removes the version rather "
        "than creating a marker"
    )
    matched, others = _wait_for(
        ctx, q_delete["url"], lambda b: _has_record(b, _KEY), timeout_s=120.0
    )
    assert matched, (
        f"the permanent delete of version {version_id} produced no notification on the "
        f"s3:ObjectRemoved:Delete destination within 120s — without this leg the empty window above "
        f"would only mean that destination was never wired; traffic seen: "
        f"{[_body(m) for m in others][:2]!r}"
    )
    delete_latency_s = time.monotonic() - started
    record = _record(_body(matched[0]), _KEY)
    assert record["eventName"] == "ObjectRemoved:Delete", (
        f"the permanent-delete notification carries eventName {record['eventName']!r}, expected "
        "'ObjectRemoved:Delete' — the two removal sub-types are being collapsed into one"
    )
    assert record["s3"]["object"]["versionId"] == version_id, (
        f"the notification reports versionId {record['s3']['object'].get('versionId')!r}; the "
        f"deleted version was {version_id!r}"
    )

    _assert_quiet(
        ctx, sqs, q_marker,
        hold_s=min(max(3.0 * delete_latency_s, 15.0), _HOLD_CAP_S),
        reason=(
            f"a permanent version delete is not a delete-marker creation, and the permanent-delete "
            f"event reached the other queue in {delete_latency_s:.1f}s"
        ),
    )

    # --- Independent read at the producer, through a third operation: the marker survived the
    # version delete and the version is gone.
    versions = s3.list_object_versions(Bucket=bucket["name"], Prefix=_PREFIX)
    surviving = [v["VersionId"] for v in versions.get("Versions", [])]
    assert surviving == [], (
        f"ListObjectVersions still reports object versions {surviving} after {version_id} was "
        "permanently deleted"
    )
    assert [m["VersionId"] for m in versions.get("DeleteMarkers", [])] == [marker_version], (
        f"ListObjectVersions reports delete markers "
        f"{[m['VersionId'] for m in versions.get('DeleteMarkers', [])]}; expected exactly the one "
        f"this check created ({marker_version!r})"
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


def _collect(ctx, queue_url, *, window_s=30.0, max_total=20):
    """Drain a queue over a bounded window with long-polling receives; return every message seen.

    This is the NEGATIVE observable. An empty return is only meaningful once a positive control has
    been observed on the same wiring — used alone it passes against a target that delivers nothing.
    """
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

    Returns (matched, others): every non-matching message seen is returned too, so the caller can
    assert on leakage. Returns empty on timeout; the caller
    asserts, which is what turns a timeout into a failure with a message."""
    matched: list = []
    others: list = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and not matched:
        for msg in _collect(ctx, queue_url, window_s=min(8.0, timeout_s)):
            (matched if predicate(_body(msg)) else others).append(msg)
    return matched, others


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the check's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _assert_quiet(ctx, sqs, queue, *, hold_s: float, reason: str) -> None:
    """Assert a queue receives NO notification record for hold_s, on two observables: an empty
    long-poll drain and ApproximateNumberOfMessages polling to 0 (the counter may lag up to a
    minute, per the SQS GetQueueAttributes docs)."""
    leaked = _collect(ctx, queue["url"], window_s=hold_s)
    keys = [
        r.get("s3", {}).get("object", {}).get("key")
        for m in leaked
        if isinstance(_body(m), dict)
        for r in _body(m).get("Records", [])
    ]
    assert keys == [], (
        f"queue {queue['name']} received notification(s) for {keys} within {hold_s:.0f}s: {reason}"
    )
    timeout_s = 90.0
    budget_s = _budget_s(ctx, timeout_s)
    start = time.monotonic()
    stop = start + min(timeout_s, budget_s)
    while True:
        attrs = sqs.get_queue_attributes(
            QueueUrl=queue["url"],
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"]
        if attrs["ApproximateNumberOfMessages"] == "0":
            break
        if time.monotonic() >= stop and budget_s < timeout_s:
            raise TimeoutError(
                f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
                f"{timeout_s}s counter wait ended ({attrs}); not graded"
            )
        assert time.monotonic() < stop, (
            f"queue {queue['name']} still reports {attrs['ApproximateNumberOfMessages']} visible "
            f"message(s) after its absence window, contradicting the empty drain: {reason}"
        )
        time.sleep(3)


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
    """TEARDOWN ONLY — never on an assertion path. Purge every version and delete marker, then
    delete the bucket."""
    s3 = ctx.client("s3")
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


def _create_versioned_bucket(ctx) -> dict:
    """Create a tagged, versioning-enabled S3 bucket with teardown registered. Returns {name,arn}."""
    name = _xname(ctx, "bkt")
    s3 = ctx.client("s3")
    kwargs: dict = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    return {"name": name, "arn": f"arn:aws:s3:::{name}"}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
