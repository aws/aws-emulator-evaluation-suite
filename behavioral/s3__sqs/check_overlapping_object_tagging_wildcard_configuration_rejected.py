"""overlapping-object-tagging-wildcard-configuration-rejected."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "overlapping-object-tagging-wildcard-configuration-rejected"
GROUP = "event-propagation"
SERVICES = ["s3", "sqs"]

_KEY = "fam/overlap.txt"


@tags(
    "axis:rejection",
    "cap:c2",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A configuration whose `s3:ObjectTagging:*` overlaps an existing `s3:ObjectTagging:Put` is
    refused whole (InvalidArgument, "Configurations overlap") and the routing already in force keeps
    delivering; a fresh bucket accepting the wildcard alone proves it was a legal destination.
    """
    s3 = ctx.client("s3")
    bucket = _create_acl_enabled_bucket(ctx)
    control_bucket = _create_acl_enabled_bucket(ctx)
    q_put = _create_queue(ctx)
    q_wild = _create_queue(ctx)
    _allow_s3_send(ctx, q_put, bucket["arn"])
    _allow_s3_send(ctx, q_wild, bucket["arn"])
    _allow_s3_send(ctx, q_wild, control_bucket["arn"])

    cfg_a = {"Id": "tagging-put", "QueueArn": q_put["arn"], "Events": ["s3:ObjectTagging:Put"]}
    cfg_b = {"Id": "tagging-any", "QueueArn": q_wild["arn"], "Events": ["s3:ObjectTagging:*"]}
    s3.put_bucket_notification_configuration(
        Bucket=bucket["name"], NotificationConfiguration={"QueueConfigurations": [cfg_a]}
    )

    err = _client_error(lambda: s3.put_bucket_notification_configuration(
        Bucket=bucket["name"], NotificationConfiguration={"QueueConfigurations": [cfg_a, cfg_b]}
    ))
    assert err["Code"] == "InvalidArgument", (
        f"an overlapping ObjectTagging:Put + ObjectTagging:* configuration returned {err!r}, "
        "expected InvalidArgument"
    )
    assert err.get("ArgumentName") == "Event", (
        f"the overlap rejection names argument {err.get('ArgumentName')!r}, expected 'Event': {err!r}"
    )
    assert err.get("Message") == (
        "Configurations overlap. Configurations on the same bucket cannot share a common event type."
    ), f"unexpected overlap rejection message {err.get('Message')!r}: {err!r}"
    assert err.get("ArgumentValue") == "s3:ObjectTagging:Put, s3:ObjectTagging:*", (
        f"the overlap rejection names value {err.get('ArgumentValue')!r}, expected "
        f"'s3:ObjectTagging:Put, s3:ObjectTagging:*': {err!r}"
    )

    got = s3.get_bucket_notification_configuration(Bucket=bucket["name"])
    installed = {c["Id"]: c["Events"] for c in got.get("QueueConfigurations", [])}
    assert installed == {"tagging-put": ["s3:ObjectTagging:Put"]}, (
        f"after the rejected replace the bucket reports {installed!r}; the rejected document must "
        "not be partially applied and the previous one must survive"
    )

    s3.put_object(Bucket=bucket["name"], Key=_KEY, Body=b"overlap-subject")
    started = time.monotonic()
    s3.put_object_tagging(Bucket=bucket["name"], Key=_KEY,
                          Tagging={"TagSet": [{"Key": "round", "Value": "1"}]})
    recs, others = _wait_for_records(ctx, q_put["url"], _KEY, timeout_s=120.0)
    assert recs, (
        f"the surviving s3:ObjectTagging:Put configuration delivered nothing within 120s; "
        f"other traffic: {others[:2]!r}"
    )
    assert recs[0]["eventName"] == "ObjectTagging:Put", (
        f"the surviving route delivered eventName {recs[0]['eventName']!r}, expected 'ObjectTagging:Put'"
    )
    latency_s = time.monotonic() - started
    hold_s = min(max(3.0 * latency_s, 15.0), 120.0)
    leaked = _drain_records(ctx, q_wild["url"], hold_s)
    assert leaked == [], (
        f"the wildcard queue from the REJECTED configuration received {leaked!r} within "
        f"{hold_s:.0f}s, while the surviving route delivered in {latency_s:.1f}s"
    )

    # Positive control: B on its own is legal and deliverable (fresh bucket: no cached routing).
    s3.put_bucket_notification_configuration(
        Bucket=control_bucket["name"], NotificationConfiguration={"QueueConfigurations": [cfg_b]}
    )
    s3.put_object(Bucket=control_bucket["name"], Key=_KEY, Body=b"overlap-control")
    s3.put_object_tagging(Bucket=control_bucket["name"], Key=_KEY,
                          Tagging={"TagSet": [{"Key": "round", "Value": "2"}]})
    recs, others = _wait_for_records(ctx, q_wild["url"], _KEY, timeout_s=120.0)
    assert recs, (
        f"the wildcard configuration, once installed alone, delivered nothing within 120s, so its "
        f"empty hold above proves nothing; other traffic: {others[:2]!r}"
    )
    assert recs[0]["s3"]["bucket"]["name"] == control_bucket["name"], (
        f"the control delivery names bucket {recs[0]['s3']['bucket'].get('name')!r}, expected "
        f"{control_bucket['name']!r}"
    )
    assert recs[0]["eventName"] == "ObjectTagging:Put", (
        f"s3:ObjectTagging:* delivered eventName {recs[0]['eventName']!r} for a tag write, "
        "expected 'ObjectTagging:Put'"
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"

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
    """Authorise s3.amazonaws.com to SendMessage, scoped to every bucket ARN granted so far."""
    queue.setdefault("sources", []).append(bucket_arn)
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowS3Send",
            "Effect": "Allow",
            "Principal": {"Service": "s3.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue["arn"],
            "Condition": {"ArnEquals": {"aws:SourceArn": queue["sources"]}},
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


def _client_error(fn) -> dict:
    """Call fn(), which MUST fail; return the botocore Error dict. Success is itself a failure."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError("the call succeeded; real AWS rejects it")


def _drain_records(ctx, queue_url: str, hold_s: float) -> list:
    """Drain a queue for hold_s; return (eventName, key) for every notification record seen."""
    sqs = ctx.client("sqs")
    seen: list = []
    deadline = time.monotonic() + hold_s
    while time.monotonic() < deadline:
        wait = min(5, max(1, int(deadline - time.monotonic())))
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            seen.extend((r.get("eventName"), r.get("s3", {}).get("object", {}).get("key"))
                        for r in _records_in(msg))
    return seen


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
