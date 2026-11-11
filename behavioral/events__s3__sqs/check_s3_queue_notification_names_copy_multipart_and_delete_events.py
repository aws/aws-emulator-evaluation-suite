"""s3-queue-notification-names-copy-multipart-and-delete-events."""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-queue-notification-names-copy-multipart-and-delete-events"

GROUP = "event-propagation"

SERVICES = ["s3", "sqs"]


def _is_s3_test_event(body: object) -> bool:
    """True for S3's one-off destination-validation handshake message.

    When a queue is first attached as an S3 notification destination, S3 posts
    {"Service":"Amazon S3","Event":"s3:TestEvent", ...} to prove it can write to
    the queue. It carries no "Records" and is NOT an object event, so it must
    never be mistaken for one (nor counted as an over-delivery).
    """
    return isinstance(body, dict) and body.get("Event") == "s3:TestEvent"


def _receive_records(ctx, queue_url: str, done, awaited, timeout_s: float = 40) -> list[dict]:
    """Every S3 object-event record the queue delivers, discarding s3:TestEvent.

    Receives until ``done(records)`` holds (bounded by ``timeout_s``), then for a further bounded
    quiet window, so a record that arrives after the awaited ones is still returned.
    """
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    quiet_until = None
    out: list[dict] = []
    while True:
        now = time.monotonic()
        if quiet_until is None and done(out):
            quiet_until = now + _QUIET_S
        if quiet_until is not None and now >= quiet_until:
            return out
        if quiet_until is None and now >= deadline:
            seen = sorted((r.get("eventName"), r["s3"]["object"].get("key")) for r in out)
            raise AssertionError(
                f"within {timeout_s:.0f}s the queue delivered {seen!r}, awaiting {awaited!r}"
            )
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        for m in resp.get("Messages", []):
            body = json.loads(m["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if _is_s3_test_event(body):
                continue
            out.extend(body.get("Records", []))


#: The quiet window after the awaited records in which any further record is still collected; a
#: bound on absence, never an assertion on elapsed time.
_QUIET_S = 10.0


def _distinct(records: list[dict]) -> list[dict]:
    """One record per event: S3 delivers at least once, so a redelivery repeats the same
    (eventName, key, versionId or sequencer) and is dropped here."""
    seen: dict = {}
    for r in records:
        obj = r["s3"]["object"]
        identity = (r.get("eventName"), obj.get("key"), obj.get("versionId") or obj.get("sequencer"))
        seen.setdefault(identity, r)
    return list(seen.values())


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
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A queue subscribed to Copy, CompleteMultipartUpload and ObjectRemoved:Delete gets one record
    per such action, named for it, with the copy's MD5 eTag, the multipart '-1' eTag and sizes, and
    none for the plain PutObject, through a later control delete and a quiet window after it.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-how-to-event-types-and-destinations.html
    """
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    queue = _create_queue(ctx)
    notification = {
        "QueueConfigurations": [
            {
                "QueueArn": queue["arn"],
                "Events": [
                    "s3:ObjectCreated:Copy",
                    "s3:ObjectCreated:CompleteMultipartUpload",
                    "s3:ObjectRemoved:Delete",
                ],
            }
        ]
    }
    _set_queue_policy(
        ctx, queue["url"], _sqs_policy_for_s3(queue["arn"], bucket["arn"])
    )
    # The configuration is accepted once S3 may send to the queue (retried through propagation).
    _put_notification_after_policy(s3, bucket["name"], notification)

    name = bucket["name"]
    source = secrets.token_bytes(500 + secrets.randbelow(500))
    s3.put_object(Bucket=name, Key="src/original.bin", Body=source)
    s3.copy_object(Bucket=name, Key="dst/copy.bin", CopySource={"Bucket": name, "Key": "src/original.bin"})
    part = secrets.token_bytes(1000 + secrets.randbelow(1000))
    upload = s3.create_multipart_upload(Bucket=name, Key="mpu/assembled.bin")["UploadId"]
    ctx.on_cleanup(_tolerant(lambda: s3.abort_multipart_upload(Bucket=name, Key="mpu/assembled.bin",
                                                               UploadId=upload), "NoSuchUpload", "NoSuchBucket"))
    etag = s3.upload_part(Bucket=name, Key="mpu/assembled.bin", UploadId=upload, PartNumber=1, Body=part)["ETag"]
    s3.complete_multipart_upload(Bucket=name, Key="mpu/assembled.bin", UploadId=upload,
                                 MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": etag}]})
    s3.delete_object(Bucket=name, Key="src/original.bin")
    # Control: a delete sent last, so its delivery bounds the PutObject's absence.
    s3.delete_object(Bucket=name, Key="dst/copy.bin")

    records = _receive_records(
        ctx, queue["url"],
        lambda rs: ("ObjectRemoved:Delete", "dst/copy.bin") in {(r.get("eventName"), r["s3"]["object"].get("key")) for r in rs}
        and len(_distinct(rs)) >= 4,
        "four records ending with ObjectRemoved:Delete of dst/copy.bin",
    )
    got = sorted(
        (r.get("eventName"), r["s3"]["object"].get("key"), r["s3"]["object"].get("size"),
         r["s3"]["object"].get("eTag"))
        for r in _distinct(records)
    )
    multipart = hashlib.md5(hashlib.md5(part).digest()).hexdigest() + "-1"
    # A removal record names the key only: it carries no size and no eTag.
    want = sorted([
        ("ObjectCreated:Copy", "dst/copy.bin", len(source), hashlib.md5(source).hexdigest()),
        ("ObjectCreated:CompleteMultipartUpload", "mpu/assembled.bin", len(part), multipart),
        ("ObjectRemoved:Delete", "src/original.bin", None, None),
        ("ObjectRemoved:Delete", "dst/copy.bin", None, None),
    ])
    assert got == want, f"expected one record per subscribed action {want!r}, got {got!r}"
    # Tear down in reverse dependency order and prove each resource gone.
    _gone_bucket(ctx, bucket["name"])
    _gone_queue(ctx, queue["name"], queue["url"])


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
    with BucketNotEmpty and leaks the bucket. Purge objects AND all
    versions/delete-markers (versioning may be on), then delete; only an already-gone bucket
    (NoSuchBucket) is tolerated."""
    s3 = ctx.client("s3")
    try:
        try:
            paginator = s3.get_paginator("list_object_versions")
            for page in paginator.paginate(Bucket=bucket):
                targets = [
                    {"Key": o["Key"], "VersionId": o["VersionId"]}
                    for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
                ]
                if targets:
                    s3.delete_objects(Bucket=bucket, Delete={"Objects": targets})
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NotImplemented", "MethodNotAllowed"):
                raise
            p2 = s3.get_paginator("list_objects_v2")
            for page in p2.paginate(Bucket=bucket):
                keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
                if keys:
                    s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_queue(ctx) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    name = _xname(ctx, "q")
    sqs = ctx.client("sqs")
    resp = sqs.create_queue(QueueName=name, tags=_xsvc_resource_tags())
    url = resp["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    ctx.on_cleanup(_tolerant(lambda: sqs.delete_queue(QueueUrl=url), *_SQS_NF))
    return {"name": name, "url": url, "arn": arn}


def _create_bucket(ctx) -> dict[str, str]:
    """Create an S3 bucket (registers empty-then-delete teardown). Returns {name,arn}."""
    name = _xname(ctx, "bkt")
    s3 = ctx.client("s3")
    create_kwargs: dict[str, Any] = {"Bucket": name}
    # us-east-1 is the one region that rejects an explicit LocationConstraint.
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(_tolerant(lambda: _empty_and_delete_bucket(ctx, name), "NoSuchBucket"))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})
    return {"name": name, "arn": f"arn:aws:s3:::{name}"}


#: Bounded convergence for a delete to reach its terminal not-found answer (the default service
#: class budget); a deadline, never an assertion on elapsed time.
_GONE_S = 40.0


def _err(exc: ClientError) -> tuple[str, int, str]:
    """(code, HTTP status, message) of a ClientError."""
    e = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return e.get("Code") or "", status, e.get("Message") or e.get("message") or ""


def _refused(fn, codes: tuple[str, ...], status: int, what: str, message: str, *, exact: bool = False) -> None:
    """``fn()`` must fail with one of ``codes`` in the HTTP class of ``status`` (exactly ``status``
    when ``exact``), with exactly the message ``message``."""
    try:
        fn()
    except ClientError as exc:
        code, got, msg = _err(exc)
        want = status if exact else f"{status // 100}xx"
        in_class = isinstance(got, int) and (got == status if exact else got // 100 == status // 100)
        assert code in codes and in_class, (
            f"{what}: expected {'/'.join(codes)} HTTP {want}, got {code!r} HTTP {got!r}: {msg[:150]!r}"
        )
        assert msg == message, f"{what}: {code} message: expected {message!r}, got {msg!r}"
        return
    raise AssertionError(f"{what}: expected {'/'.join(codes)} HTTP {status}, the call succeeded")


def _poll_refused(fn, codes, status, what, message, timeout_s: float = _GONE_S, exact: bool = False) -> None:
    """Poll ``fn`` until it reaches the terminal not-found answer, then grade it with ``_refused``.

    A success while the delete converges is retried; any other error fails at once.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            code, _, _ = _err(exc)
            if code in codes:
                _refused(fn, codes, status, what, message, exact=exact)
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: still readable {timeout_s:.0f}s after the delete")
        time.sleep(1.0)


def _poll_absent(listing, what: str, timeout_s: float = _GONE_S) -> None:
    """Poll ``listing()`` until it is empty (bounded); fail with ``what`` and the last listing."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = listing()
        if not last:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} {timeout_s:.0f}s after the delete: {last!r}")
        time.sleep(1.0)


def _put_notification_after_policy(s3, bucket: str, notification: dict) -> None:
    """PutBucketNotificationConfiguration must succeed once S3 may send to the queue."""
    deadline = time.monotonic() + 30.0
    while True:
        try:
            s3.put_bucket_notification_configuration(
                Bucket=bucket, NotificationConfiguration=notification
            )
            return
        except ClientError as exc:
            if _err(exc)[0] != "InvalidArgument" or time.monotonic() >= deadline:
                raise
        time.sleep(2.0)


def _tolerant(fn, *codes: str):
    """A teardown that ignores only the given not-found codes (the body already deleted it)."""

    def run() -> None:
        try:
            fn()
        except ClientError as exc:
            if _err(exc)[0] not in codes:
                raise

    return run


_SQS_NF = ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist")
_SQS_GONE = "The specified queue does not exist."


def _gone_queue(ctx, name: str, url: str) -> None:
    sqs = ctx.client("sqs")
    sqs.delete_queue(QueueUrl=url)
    # AWS documents up to 60 s for a deleted queue to stop answering.
    _poll_refused(lambda: sqs.get_queue_url(QueueName=name), _SQS_NF, 400, f"GetQueueUrl {name}", _SQS_GONE)
    # The listing and the URL need not converge at the same instant: each is polled.
    _poll_absent(
        lambda: [
            u
            for u in sqs.list_queues(QueueNamePrefix=name).get("QueueUrls", [])
            if u.rstrip("/").split("/")[-1] == name
        ],
        f"ListQueues still lists deleted queue {name}",
    )
    _poll_refused(lambda: sqs.send_message(QueueUrl=url, MessageBody="gone"), _SQS_NF, 400, f"SendMessage {name}", _SQS_GONE)


def _empty_bucket(s3, bucket: str) -> None:
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        objs = [{"Key": o["Key"], "VersionId": o["VersionId"]} for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs, "Quiet": True})


def _gone_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    _empty_bucket(s3, bucket)
    s3.delete_bucket(Bucket=bucket)
    # HeadBucket has no body: the code is the bare status.
    _poll_refused(lambda: s3.head_bucket(Bucket=bucket), ("404",), 404, f"HeadBucket {bucket}", "Not Found", exact=True)
    names = {b["Name"] for b in s3.list_buckets(Prefix=bucket).get("Buckets", [])}
    assert bucket not in names, f"ListBuckets still lists deleted bucket {bucket}"
    _refused(lambda: s3.put_object(Bucket=bucket, Key="gone", Body=b"x"), ("NoSuchBucket",), 404, f"PutObject {bucket}",
             "The specified bucket does not exist")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
