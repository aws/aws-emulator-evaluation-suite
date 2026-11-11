"""s3-notification-to-sqs-direct."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-notification-to-sqs-direct"

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
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """S3 bucket notifications deliver ObjectCreated events directly to SQS."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    queue = _create_queue(ctx)

    notification = {
        "QueueConfigurations": [
            {"QueueArn": queue["arn"], "Events": ["s3:ObjectCreated:*"]}
        ]
    }
    _set_queue_policy(
        ctx, queue["url"], _sqs_policy_for_s3(queue["arn"], bucket["arn"])
    )

    # The configuration is accepted once S3 may send to the queue (retried through propagation).
    _put_notification_after_policy(s3, bucket["name"], notification)

    key = f"{ctx.unique_name('obj-')}.txt"
    s3.put_object(Bucket=bucket["name"], Key=key, Body=b"hi")

    messages = _wait_for_s3_records(ctx, queue["url"], expected_count=1, timeout_s=90)
    assert messages, "expected S3 event notification in SQS queue"
    body = messages[0]["body"]
    records = body.get("Records", [])
    assert records, f"malformed S3 notification body: {body}"
    assert records[0]["s3"]["bucket"]["name"] == bucket["name"], (
        f"expected bucket {bucket['name']!r}, got {records[0]['s3']['bucket'].get('name')!r}"
    )
    assert records[0]["s3"]["object"]["key"] == key, (
        f"expected key {key!r}, got {records[0]['s3']['object'].get('key')!r}"
    )
    assert records[0].get("eventSource") == "aws:s3", (
        f"expected eventSource 'aws:s3', got {records[0].get('eventSource')!r}"
    )
    assert records[0].get("awsRegion") == ctx.region, (
        f"expected awsRegion {ctx.region!r}, got {records[0].get('awsRegion')!r}"
    )
    assert str(records[0].get("eventName", "")).startswith("ObjectCreated:"), (
        f"expected eventName 'ObjectCreated:*', got {records[0].get('eventName')!r}"
    )
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
    try:
        s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})
    except ClientError:
        pass
    return {"name": name, "arn": f"arn:aws:s3:::{name}"}


#: Bounded convergence for a delete to reach its terminal not-found answer (the default service
#: class budget); a deadline, never an assertion on elapsed time.
_GONE_S = 120.0


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


def _paged(client, op: str, key: str, **kw) -> list:
    """Every element of ``key`` across all pages of ``op``."""
    out: list = []
    for page in client.get_paginator(op).paginate(**kw):
        out.extend(page.get(key, []))
    return out


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
    _poll_refused(lambda: s3.head_bucket(Bucket=bucket), ("404", "NoSuchBucket", "NotFound"), 404, f"HeadBucket {bucket}", "Not Found", exact=True)
    names = {b["Name"] for b in s3.list_buckets(Prefix=bucket).get("Buckets", [])}
    assert bucket not in names, f"ListBuckets still lists deleted bucket {bucket}"
    _refused(lambda: s3.put_object(Bucket=bucket, Key="gone", Body=b"x"), ("NoSuchBucket",), 404, f"PutObject {bucket}",
             "The specified bucket does not exist")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
