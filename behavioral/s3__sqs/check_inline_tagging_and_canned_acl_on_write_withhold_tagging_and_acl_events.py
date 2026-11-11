"""inline-tagging-and-canned-acl-on-write-withhold-tagging-and-acl-events."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "inline-tagging-and-canned-acl-on-write-withhold-tagging-and-acl-events"
GROUP = "event-propagation"
SERVICES = ["s3", "sqs"]

_KEY = "fam/written-with-tags-and-acl.txt"
_COPY_KEY = "fam/copied-with-tags-and-acl.txt"


@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutObject/CopyObject carrying tags and a canned ACL emit only ObjectCreated:Put/Copy, never
    ObjectTagging:Put or ObjectAcl:Put; standalone tagging and ACL writes then reach those same
    queues, proving they were wired.
    """
    s3 = ctx.client("s3")
    bucket = _create_acl_enabled_bucket(ctx)
    control = _create_queue(ctx)
    _allow_s3_send(ctx, control, bucket["arn"])
    queues = _wire_family_queues(ctx, bucket, extra=[
        {"Id": "control-put", "QueueArn": control["arn"], "Events": ["s3:ObjectCreated:Put"]},
    ])

    started = time.monotonic()
    s3.put_object(Bucket=bucket["name"], Key=_KEY, Body=b"inline-meta", Tagging="stage=draft",
                  ACL="private")
    s3.copy_object(
        Bucket=bucket["name"], Key=_COPY_KEY, CopySource={"Bucket": bucket["name"], "Key": _KEY},
        TaggingDirective="REPLACE", Tagging="stage=copied", ACL="private",
    )

    put_recs, others = _wait_for_records(ctx, control["url"], _KEY, timeout_s=120.0)
    assert put_recs, (
        f"the control s3:ObjectCreated:Put queue received nothing for {_KEY!r} within 120s, so no "
        f"absence below would mean anything; other traffic: {others[:2]!r}"
    )
    assert put_recs[0]["eventName"] == "ObjectCreated:Put", (
        f"the control record carries eventName {put_recs[0]['eventName']!r}, expected 'ObjectCreated:Put'"
    )
    copy_recs, others = _wait_for_records(ctx, queues["created-copy"]["url"], _COPY_KEY, timeout_s=120.0)
    assert copy_recs, (
        f"the s3:ObjectCreated:Copy queue received nothing for {_COPY_KEY!r} within 120s; "
        f"other traffic: {others[:2]!r}"
    )
    assert copy_recs[0]["eventName"] == "ObjectCreated:Copy", (
        f"the copy record carries eventName {copy_recs[0]['eventName']!r}, expected 'ObjectCreated:Copy'"
    )
    latency_s = time.monotonic() - started

    stored = s3.get_object_tagging(Bucket=bucket["name"], Key=_COPY_KEY)["TagSet"]
    assert stored == [{"Key": "stage", "Value": "copied"}], (
        f"the copy's tags are {stored!r}; the REPLACE directive must have applied, or the absence "
        "below proves nothing about a tag write"
    )

    # The control/copy arrivals bound how long the tagging/ACL queues must stay silent.
    hold_s = min(max(3.0 * latency_s, 15.0), 120.0)
    _assert_family_quiet(ctx, queues, subject="created-copy", expected_name="ObjectCreated:Copy",
                         hold_s=hold_s, latency_s=latency_s)

    # Close the loop: the same queues DO receive a standalone tagging write and ACL write.
    s3.put_object_tagging(Bucket=bucket["name"], Key=_KEY,
                          Tagging={"TagSet": [{"Key": "stage", "Value": "final"}]})
    s3.put_object_acl(Bucket=bucket["name"], Key=_KEY, ACL="private")
    for label, name in (("tagging-put", "ObjectTagging:Put"), ("acl-put", "ObjectAcl:Put")):
        recs, others = _wait_for_records(ctx, queues[label]["url"], _KEY, timeout_s=120.0)
        assert recs, (
            f"the {label} queue received nothing for a standalone write within 120s, so its empty "
            f"hold above only proved it was never wired; other traffic: {others[:2]!r}"
        )
        assert recs[0]["eventName"] == name, (
            f"the standalone {label} write carries eventName {recs[0]['eventName']!r}, expected {name!r}"
        )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"

#: label -> the ONE event type that label's queue subscribes to.
_FAMILIES = {
    "tagging-put": "s3:ObjectTagging:Put",
    "tagging-delete": "s3:ObjectTagging:Delete",
    "acl-put": "s3:ObjectAcl:Put",
    "created-copy": "s3:ObjectCreated:Copy",
}


def _xsvc_tags_kv() -> list:
    return [{"Key": _MANAGED_TAG_KEY, "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}]


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _create_queue(ctx) -> dict:
    """Create a tagged SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    sqs = ctx.client("sqs")
    name = _xname(ctx, "q")
    url = sqs.create_queue(QueueName=name, tags={_MANAGED_TAG_KEY: "true"})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return {"name": name, "url": url, "arn": arn}


def _allow_s3_send(ctx, queue: dict, bucket_arn: str) -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowS3Send",
            "Effect": "Allow",
            "Principal": {"Service": "s3.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue["arn"],
            "Condition": {"ArnEquals": {"aws:SourceArn": bucket_arn}},
        }],
    }
    ctx.client("sqs").set_queue_attributes(QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)})


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    """TEARDOWN ONLY. Purge every version and delete marker, then delete the bucket."""
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            targets = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if targets:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": targets})
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchBucket":
            return
        raise
    s3.delete_bucket(Bucket=bucket)


def _create_acl_enabled_bucket(ctx) -> dict:
    """A tagged bucket with ObjectOwnership=BucketOwnerPreferred, so object ACL writes are legal
    (the default BucketOwnerEnforced rejects PutObjectAcl with AccessControlListNotSupported)."""
    s3 = ctx.client("s3")
    name = _xname(ctx, "bkt")
    kwargs: dict = {"Bucket": name, "ObjectOwnership": "BucketOwnerPreferred"}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})
    return {"name": name, "arn": f"arn:aws:s3:::{name}"}


def _wire_family_queues(ctx, bucket: dict, extra=None) -> dict:
    """One queue per _FAMILIES entry, each subscribed to exactly its one event type, plus any
    `extra` QueueConfigurations (whose queues the caller created and authorised)."""
    s3 = ctx.client("s3")
    queues = {}
    for label in _FAMILIES:
        q = _create_queue(ctx)
        _allow_s3_send(ctx, q, bucket["arn"])
        queues[label] = q
    config = {
        "QueueConfigurations": [
            {"Id": label, "QueueArn": queues[label]["arn"], "Events": [event]}
            for label, event in _FAMILIES.items()
        ] + list(extra or [])
    }
    s3.put_bucket_notification_configuration(
        Bucket=bucket["name"], NotificationConfiguration=config
    )
    got = s3.get_bucket_notification_configuration(Bucket=bucket["name"])
    installed = {c["Id"]: c["Events"] for c in got.get("QueueConfigurations", [])}
    expected = {label: [event] for label, event in _FAMILIES.items()}
    expected.update({c["Id"]: c["Events"] for c in extra or []})
    assert installed == expected, (
        f"GetBucketNotificationConfiguration reports {installed!r}; expected {expected!r}"
    )
    return queues


def _records_in(msg: dict) -> list:
    try:
        body = json.loads(msg.get("Body", ""))
    except (json.JSONDecodeError, ValueError):
        return []
    return body.get("Records", []) if isinstance(body, dict) else []


def _wait_for_records(ctx, queue_url: str, key: str, *, timeout_s: float):
    """Long-poll a queue until a Records entry for `key` arrives. Returns (records, others):
    every record for `key` in the batch that satisfied the wait, plus every other body seen."""
    sqs = ctx.client("sqs")
    others: list = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        found = []
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            recs = [
                r for r in _records_in(msg)
                if r.get("s3", {}).get("object", {}).get("key") == key
            ]
            if recs:
                found.extend(recs)
            else:
                others.append(msg.get("Body", "")[:200])
        if found:
            return found, others
    return [], others


def _assert_family_quiet(ctx, queues: dict, *, subject: str, expected_name: str,
                         hold_s: float, latency_s: float) -> None:
    """Round-robin drain every family queue for hold_s. The non-subject queues must receive no
    notification record at all; any late copy on the subject queue must carry expected_name.
    Then each non-subject queue must report ApproximateNumberOfMessages == 0."""
    sqs = ctx.client("sqs")
    leaked: dict = {label: [] for label in queues}
    deadline = time.monotonic() + hold_s
    while time.monotonic() < deadline:
        for label, q in queues.items():
            resp = sqs.receive_message(QueueUrl=q["url"], MaxNumberOfMessages=10, WaitTimeSeconds=1)
            for msg in resp.get("Messages", []):
                sqs.delete_message(QueueUrl=q["url"], ReceiptHandle=msg["ReceiptHandle"])
                for r in _records_in(msg):
                    leaked[label].append(
                        (r.get("eventName"), r.get("s3", {}).get("object", {}).get("key"))
                    )
    late = leaked.pop(subject)
    assert all(name == expected_name for name, _ in late), (
        f"a later copy on the {subject} queue carried {late!r}; every copy must be {expected_name!r}"
    )
    assert leaked == {label: [] for label in leaked}, (
        f"sibling queues received notification records within {hold_s:.0f}s: {leaked!r}; the "
        f"subject event reached its own queue in {latency_s:.1f}s, so these are mis-routed, and "
        f"each sibling subscribes to exactly one other event type: "
        f"{ {k: v for k, v in _FAMILIES.items() if k != subject}!r}"
    )
    for label, q in queues.items():
        if label == subject:
            continue
        depth = sqs.get_queue_attributes(
            QueueUrl=q["url"], AttributeNames=["ApproximateNumberOfMessages"]
        )["Attributes"]["ApproximateNumberOfMessages"]
        assert depth == "0", (
            f"the {label} queue reports {depth} visible message(s) after an empty drain"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
