"""a-denied-put-creates-no-object-and-emits-no-notification."""

from __future__ import annotations

import json
import time
import urllib.parse
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "a-denied-put-creates-no-object-and-emits-no-notification"
GROUP = "event-propagation"
SERVICES = ["s3", "sqs"]

_ALLOWED_PREFIX = "allowed/"
_DENIED_PREFIX = "denied/"
_DENY_SID = "Sim2realDenyDeniedPrefixPut"
#: The worst-case wall clock this check can consume, declared so the suite's time budget covers
#: its sequential polls, which together run longer than any single `timeout_s=` literal. The
#: name's seconds suffix is what the budget derivation reads; do not rename it.
_WORST_CASE_BUDGET_S = 420


# ===== helpers (self-contained) =====
def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    """A bounded retry that RAISES on its deadline; never returns its last value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _error(fn):
    """The (code, message) of the ClientError raised by fn(). RAISES if fn() unexpectedly
    SUCCEEDS — a falsy sentinel would let an over-permissive target pass off acceptance as a
    code mismatch."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to be rejected but it succeeded")


def _put_status(ctx, bucket, key, body):
    """The HTTP status a PutObject answers with: 200 when accepted, the error's status when
    refused. Used only to POLL for a policy change; the refusal itself is graded via `_error`."""
    try:
        ctx.client("s3").put_object(Bucket=bucket, Key=key, Body=body)
    except ClientError as exc:
        return exc.response["ResponseMetadata"]["HTTPStatusCode"]
    return 200


def _create_bucket(ctx, check_tag):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-nd-deniedput-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":  # region-pinned API quirk, not a hardcoded region
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(ctx, name))
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={
            "TagSet": [
                {"Key": "sim2real:managed", "Value": "true"},
                {"Key": "sim2real-check", "Value": check_tag},
            ]
        },
    )
    return name


def _delete_bucket(ctx, name):
    s3 = ctx.client("s3")
    try:
        s3.delete_bucket_policy(Bucket=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in (
            "NoSuchBucketPolicy",
            "NoSuchBucket",
        ):
            raise
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=name):
        stale = [
            {"Key": o["Key"], "VersionId": o["VersionId"]}
            for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
        ]
        if stale:
            s3.delete_objects(Bucket=name, Delete={"Objects": stale})
    s3.delete_bucket(Bucket=name)


def _make_queue(ctx, name, bucket, account, check_tag):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=name, tags={"sim2real-check": check_tag})["QueueUrl"]
    ctx.on_cleanup(lambda u=url: ctx.client("sqs").delete_queue(QueueUrl=u))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    sqs.set_queue_attributes(
        QueueUrl=url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowS3",
                            "Effect": "Allow",
                            "Principal": {"Service": "s3.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": arn,
                            "Condition": {
                                "StringEquals": {"aws:SourceAccount": account},
                                "ArnLike": {"aws:SourceArn": f"arn:*:s3:::{bucket}"},
                            },
                        }
                    ],
                }
            )
        },
    )
    return url, arn


def _drain_records(ctx, url, *, seconds):
    """Every S3 event record seen, URL-decoded. `.get("Messages", [])` and `.get("Records", [])` both
    feed a loop whose result is asserted by exact membership — the sanctioned polarity for an empty
    default (an S3 test-event message legitimately carries no Records)."""
    sqs = ctx.client("sqs")
    out = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            for record in body.get("Records", []):
                out.append(
                    {
                        "eventName": record["eventName"],
                        "key": urllib.parse.unquote_plus(record["s3"]["object"]["key"]),
                        "bucket": record["s3"]["bucket"]["name"],
                        "size": record["s3"]["object"].get("size"),
                    }
                )
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _queue_depth(ctx, url):
    attrs = ctx.client("sqs").get_queue_attributes(
        QueueUrl=url,
        AttributeNames=[
            "ApproximateNumberOfMessages",
            "ApproximateNumberOfMessagesNotVisible",
            "ApproximateNumberOfMessagesDelayed",
        ],
    )["Attributes"]
    return sum(int(v) for v in attrs.values())


def _deny_policy(bucket):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": _DENY_SID,
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:PutObject",
                    "Resource": f"arn:aws:s3:::{bucket}/{_DENIED_PREFIX}*",
                }
            ],
        }
    )


# ===== the check =====
@tags(
    "axis:negative-delivery",
    "cap:c7",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A PutObject the bucket policy denies creates no object and emits no ObjectCreated
    notification, and the identical PutObject emits one once the Deny is removed."""
    s3 = ctx.client("s3")
    caller = ctx.client("sts").get_caller_identity()
    account = caller["Account"]
    check_tag = CHECK
    suffix = uuid.uuid4().hex[:10]

    bucket = _create_bucket(ctx, check_tag)
    queue_url, queue_arn = _make_queue(
        ctx, f"sim2real-nd-deniedput-{suffix}", bucket, account, check_tag
    )
    # The subscription is DELIBERATELY as wide as it can be: every object-creation event, no prefix,
    # no suffix. Nothing about the subscription can explain an absence.
    s3.put_bucket_notification_configuration(
        Bucket=bucket,
        NotificationConfiguration={
            "QueueConfigurations": [
                {"Id": "all-creates", "QueueArn": queue_arn, "Events": ["s3:ObjectCreated:*"]}
            ]
        },
    )
    stored = s3.get_bucket_notification_configuration(Bucket=bucket)["QueueConfigurations"]
    assert [c["Events"] for c in stored] == [["s3:ObjectCreated:*"]], (
        f"the stored notification configuration is {stored!r}, expected a single unfiltered "
        f"s3:ObjectCreated:* subscription — a narrower one would give the absence below a second "
        f"possible explanation"
    )
    assert stored[0]["QueueArn"] == queue_arn, (
        f"the stored configuration points at {stored[0]['QueueArn']!r}, expected {queue_arn!r}"
    )
    _drain_records(ctx, queue_url, seconds=8)  # discard S3's s3:TestEvent probe message

    # BEAT 1 — a permitted write, on this exact bucket and queue, measures L.
    allowed_key = f"{_ALLOWED_PREFIX}ok-{suffix}.bin"
    payload = b"z" * 777
    t0 = time.monotonic()
    s3.put_object(Bucket=bucket, Key=allowed_key, Body=payload)
    records = _poll_until(
        lambda: _drain_records(ctx, queue_url, seconds=5),
        lambda recs: any(r["key"] == allowed_key for r in recs),
        timeout_s=180,
        interval_s=0,
        description=(
            f"the permitted write to {allowed_key!r} produced an ObjectCreated notification on "
            f"{queue_url} — the positive control that makes the absence below evidence"
        ),
    )
    latency = max(time.monotonic() - t0, 1.0)
    good = next(r for r in records if r["key"] == allowed_key)
    assert good["eventName"].startswith("ObjectCreated:"), (
        f"the notification for {allowed_key!r} carries eventName={good['eventName']!r}, expected an "
        f"ObjectCreated:* value"
    )
    assert good["size"] == len(payload), (
        f"the notification for {allowed_key!r} reports size={good['size']!r}, expected "
        f"{len(payload)} — a record whose size does not match the committed bytes is not derived "
        f"from the committed write"
    )

    # BREAK EXACTLY ONE THING — a resource-policy Deny scoped to one prefix, so cleanup and the
    # control prefix are untouched.
    s3.put_bucket_policy(Bucket=bucket, Policy=_deny_policy(bucket))
    ctx.on_cleanup(lambda: _drop_policy(ctx, bucket))
    assert _DENY_SID in s3.get_bucket_policy(Bucket=bucket)["Policy"], (
        f"PutBucketPolicy did not attach {_DENY_SID!r} to {bucket}: "
        f"{s3.get_bucket_policy(Bucket=bucket)['Policy']!r}"
    )

    denied_key = f"{_DENIED_PREFIX}blocked-{suffix}.bin"
    _poll_until(
        lambda: _put_status(ctx, bucket, denied_key, payload),
        lambda status: status == 403,
        timeout_s=120,
        interval_s=3,
        description=(
            f"the bucket policy Deny took effect and PutObject on {denied_key!r} is refused (S3 "
            f"policies are eventually consistent, so this is a bounded retry over the OBSERVED "
            f"behaviour rather than a fixed wait)"
        ),
    )
    # The graded attempt goes through `_error`, which RAISES on success — so an over-permissive
    # target cannot pass off acceptance as a code mismatch.
    code, message = _error(
        lambda: ctx.client("s3").put_object(Bucket=bucket, Key=denied_key, Body=payload)
    )
    assert code == "AccessDenied", (
        f"PutObject on {denied_key!r} was refused with {code!r}, expected 'AccessDenied' for an "
        f"explicit resource-policy Deny"
    )
    # S3 names the refused caller and the exact object ARN in an explicit-deny refusal.
    expected_message = (
        f"User: {caller['Arn']} is not authorized to perform: s3:PutObject on resource: "
        f'"arn:aws:s3:::{bucket}/{denied_key}" with an explicit deny in a resource-based policy'
    )
    assert message == expected_message, (
        f"PutObject on {denied_key!r} was refused with message {message!r}, expected "
        f"{expected_message!r}"
    )

    # STRUCTURAL second observable: there is no object, so there is nothing to notify
    # about. This is what separates this check from a filter-based negative.
    head_code, head_message = _error(
        lambda: ctx.client("s3").head_object(Bucket=bucket, Key=denied_key)
    )
    assert (head_code, head_message) == ("404", "Not Found"), (
        f"head_object on the denied key {denied_key!r} answered {head_code!r} / {head_message!r}, "
        f"expected a not-found — if the object EXISTS the write was not actually denied and the "
        f"absence below would be a lost notification, not a withheld one"
    )
    listed = s3.list_objects_v2(Bucket=bucket, Prefix=_DENIED_PREFIX).get("KeyCount")
    assert listed == 0, (
        f"ListObjectsV2 reports KeyCount={listed!r} under {_DENIED_PREFIX!r}, expected 0"
    )

    # THE NEGATIVE, held for 3L and confirmed by queue depth.
    hold = max(3 * latency, 15.0)
    leaked = _drain_records(ctx, queue_url, seconds=hold)
    assert leaked == [], (
        f"the queue received {len(leaked)} notification record(s) during a {hold:.0f}s hold (3x the "
        f"{latency:.0f}s measured latency) for writes that were REFUSED and created no object: "
        f"{leaked!r} — a notification emitted from the request rather than the committed write points "
        f"a consumer at an object that does not exist"
    )
    assert _queue_depth(ctx, queue_url) == 0, (
        f"the queue reports depth {_queue_depth(ctx, queue_url)} behind an empty receive — the second "
        f"independent observable disagrees with the first"
    )

    # BEATS 5 and 6 — restore, then the IDENTICAL call on the SAME key must succeed AND notify.
    s3.delete_bucket_policy(Bucket=bucket)
    _poll_until(
        lambda: _put_status(ctx, bucket, denied_key, payload),
        lambda status: status == 200,
        timeout_s=120,
        interval_s=3,
        description=(
            f"with the Deny removed, the identical PutObject on {denied_key!r} is accepted again"
        ),
    )
    restored = _poll_until(
        lambda: _drain_records(ctx, queue_url, seconds=5),
        lambda recs: any(r["key"] == denied_key for r in recs),
        timeout_s=180,
        interval_s=0,
        description=(
            f"the previously withheld notification for {denied_key!r} is emitted once the write is "
            f"permitted — the restore beat, on the same key and the same wiring"
        ),
    )
    now_good = next(r for r in restored if r["key"] == denied_key)
    assert now_good["eventName"].startswith("ObjectCreated:"), (
        f"the restored notification carries eventName={now_good['eventName']!r}, expected an "
        f"ObjectCreated:* value"
    )
    assert now_good["bucket"] == bucket and now_good["size"] == len(payload), (
        f"the restored notification reports bucket={now_good['bucket']!r} size={now_good['size']!r}, "
        f"expected {bucket!r} and {len(payload)}"
    )
    assert s3.head_object(Bucket=bucket, Key=denied_key)["ContentLength"] == len(payload), (
        f"the object {denied_key!r} does not exist at the expected size after the permitted write"
    )


def _drop_policy(ctx, bucket):
    try:
        ctx.client("s3").delete_bucket_policy(Bucket=bucket)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("NoSuchBucketPolicy", "NoSuchBucket"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
