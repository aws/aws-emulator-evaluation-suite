"""s3-object-created-notifies-sns."""

from __future__ import annotations

import json
import time
from typing import Any
from urllib.parse import unquote_plus

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-object-created-notifies-sns"

GROUP = "data-delivery"

SERVICES = ["s3", "sns", "sqs"]


def _topic_publishable_by_s3(ctx, topic: dict, bucket_arn: str) -> None:
    """Attach an SNS topic policy allowing s3.amazonaws.com to publish for this bucket."""
    account = topic["arn"].split(":")[4]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "s3.amazonaws.com"},
                "Action": "sns:Publish",
                "Resource": topic["arn"],
                "Condition": {
                    "ArnLike": {"aws:SourceArn": bucket_arn},
                    "StringEquals": {"aws:SourceAccount": account},
                },
            }
        ],
    }
    ctx.client("sns").set_topic_attributes(
        TopicArn=topic["arn"], AttributeName="Policy", AttributeValue=json.dumps(policy)
    )


def _queue_subscribed_to_topic(ctx, topic: dict) -> dict:
    """Create an SQS queue subscribed to the topic (with the queue policy SNS needs). Returns queue."""
    queue = _create_queue(ctx)
    sqs = ctx.client("sqs")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue["arn"],
                "Condition": {"ArnEquals": {"aws:SourceArn": topic["arn"]}},
            }
        ],
    }
    sqs.set_queue_attributes(
        QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)}
    )
    sub = ctx.client("sns").subscribe(
        TopicArn=topic["arn"], Protocol="sqs", Endpoint=queue["arn"]
    )
    ctx.on_cleanup(
        _tolerant(
            lambda: ctx.client("sns").unsubscribe(SubscriptionArn=sub["SubscriptionArn"]),
            "NotFound",
        )
    )
    return {**queue, "sub": sub["SubscriptionArn"]}


def _wait_for_object_created(
    ctx, queue_url: str, key: str, timeout_s: float = 120
) -> tuple[dict, dict]:
    """Drain SNS->SQS messages until an S3 ObjectCreated event for `key` arrives.

    Returns (record, SNS envelope).

    Skips the `s3:TestEvent` S3 emits when a notification is first configured (it has no Records)
    and any unrelated notification. S3 URL-encodes the object key in the event, so compare decoded.
    """
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    seen: list = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            try:
                envelope = json.loads(msg["Body"])
                event = json.loads(envelope["Message"])
            except (json.JSONDecodeError, KeyError, TypeError):
                continue
            if event.get("Event") == "s3:TestEvent" or "Records" not in event:
                continue  # S3's config-time probe, not a real object event
            for r in event["Records"]:
                evt_key = unquote_plus(r.get("s3", {}).get("object", {}).get("key", ""))
                seen.append(evt_key)
                if evt_key == key:
                    return r, envelope
    raise AssertionError(
        f"S3 ObjectCreated event for {key!r} never delivered via SNS (saw {seen})"
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
    """A PutObject to a bucket with an SNS TopicConfiguration delivers an ObjectCreated event,
    carrying the exact object key, to the topic and on to a subscribed SQS queue."""
    bucket = _create_bucket(ctx)
    topic = _create_topic(ctx)
    _topic_publishable_by_s3(ctx, topic, bucket["arn"])
    queue = _queue_subscribed_to_topic(ctx, topic)

    ctx.client("s3").put_bucket_notification_configuration(
        Bucket=bucket["name"],
        NotificationConfiguration={
            "TopicConfigurations": [
                {"TopicArn": topic["arn"], "Events": ["s3:ObjectCreated:*"]}
            ]
        },
    )
    key = f"probe/{ctx.unique_name('obj-')}.txt"
    ctx.client("s3").put_object(Bucket=bucket["name"], Key=key, Body=b"payload")

    record, envelope = _wait_for_object_created(ctx, queue["url"], key)
    assert record["eventName"].startswith("ObjectCreated"), (
        f"unexpected eventName {record.get('eventName')!r}"
    )
    assert envelope.get("TopicArn") == topic["arn"], (
        f"expected envelope TopicArn {topic['arn']!r}, got {envelope.get('TopicArn')!r}"
    )
    got_bucket = record.get("s3", {}).get("bucket", {}).get("name")
    assert got_bucket == bucket["name"], (
        f"expected record bucket {bucket['name']!r}, got {got_bucket!r}"
    )
    # Tear down in reverse dependency order and prove each resource gone.
    _gone_subscription(ctx, queue["sub"], topic["arn"])
    _gone_topic(ctx, topic["arn"])
    _gone_queue(ctx, queue["name"], queue["url"])
    _gone_bucket(ctx, bucket["name"])


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
    """Purge all objects, versions and delete markers, then delete the bucket; a non-empty bucket
    fails with BucketNotEmpty."""
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        targets = [
            {"Key": o["Key"], "VersionId": o["VersionId"]}
            for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
        ]
        if targets:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": targets})
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
    ctx.on_cleanup(_tolerant(lambda: sqs.delete_queue(QueueUrl=url), *_SQS_NF))
    return {"name": name, "url": url, "arn": arn}


def _create_topic(ctx) -> dict[str, str]:
    """Create an SNS topic (registers delete_topic teardown). Returns {name,arn}."""
    name = _xname(ctx, "topic")
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=name, Tags=_xsvc_tags_kv())["TopicArn"]
    ctx.on_cleanup(_tolerant(lambda: sns.delete_topic(TopicArn=arn), "NotFound"))
    return {"name": name, "arn": arn}


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


def _refused(fn, codes: tuple[str, ...], status: int, what: str, message: str) -> None:
    """``fn()`` must fail with one of ``codes`` at ``status`` and exactly ``message``."""
    try:
        fn()
    except ClientError as exc:
        code, got, msg = _err(exc)
        assert code in codes and got == status, (
            f"{what}: expected {'/'.join(codes)} HTTP {status}, got {code!r} HTTP {got!r}: {msg[:150]!r}"
        )
        assert msg == message, f"{what}: {code} message is {msg[:200]!r}, expected {message!r}"
        return
    raise AssertionError(f"{what}: expected {'/'.join(codes)} HTTP {status}, the call succeeded")


def _poll_refused(fn, codes, status, what, message, timeout_s: float = _GONE_S) -> None:
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
                _refused(fn, codes, status, what, message)
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: still readable {timeout_s:.0f}s after the delete")
        time.sleep(1.0)


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
_SQS_NF_MSG = "The specified queue does not exist."


def _gone_subscription(ctx, sub_arn: str, topic_arn: str) -> None:
    sns = ctx.client("sns")
    sns.unsubscribe(SubscriptionArn=sub_arn)
    nf = ("NotFound",)
    _poll_refused(lambda: sns.get_subscription_attributes(SubscriptionArn=sub_arn), nf, 404, "GetSubscriptionAttributes", "Subscription does not exist")
    listed = {s["SubscriptionArn"] for s in _paged(sns, "list_subscriptions_by_topic", "Subscriptions", TopicArn=topic_arn)}
    assert sub_arn not in listed, "ListSubscriptionsByTopic still lists the removed subscription"
    _refused(
        lambda: sns.set_subscription_attributes(SubscriptionArn=sub_arn, AttributeName="RawMessageDelivery", AttributeValue="true"),
        nf, 404, "SetSubscriptionAttributes on removed subscription", "Subscription does not exist",
    )


def _gone_topic(ctx, arn: str) -> None:
    sns = ctx.client("sns")
    sns.delete_topic(TopicArn=arn)
    nf = ("NotFound",)
    _poll_refused(lambda: sns.get_topic_attributes(TopicArn=arn), nf, 404, "GetTopicAttributes", "Topic does not exist")
    listed = {t["TopicArn"] for t in _paged(sns, "list_topics", "Topics")}
    assert arn not in listed, "ListTopics still lists the deleted topic"
    _refused(lambda: sns.publish(TopicArn=arn, Message="gone"), nf, 404, "Publish to deleted topic", "Topic does not exist")


def _gone_queue(ctx, name: str, url: str) -> None:
    sqs = ctx.client("sqs")
    sqs.delete_queue(QueueUrl=url)
    # AWS documents up to 60 s for a deleted queue to stop answering.
    _poll_refused(lambda: sqs.get_queue_url(QueueName=name), _SQS_NF, 400, f"GetQueueUrl {name}", _SQS_NF_MSG)
    listed = sqs.list_queues(QueueNamePrefix=name).get("QueueUrls", [])
    assert not [u for u in listed if u.rstrip("/").split("/")[-1] == name], (
        f"ListQueues still lists deleted queue {name}"
    )
    _refused(lambda: sqs.send_message(QueueUrl=url, MessageBody="gone"), _SQS_NF, 400, f"SendMessage {name}", _SQS_NF_MSG)


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
    _poll_refused(lambda: s3.head_bucket(Bucket=bucket), ("404", "NoSuchBucket", "NotFound"), 404, f"HeadBucket {bucket}", "Not Found")
    names = {b["Name"] for b in s3.list_buckets(Prefix=bucket).get("Buckets", [])}
    assert bucket not in names, f"ListBuckets still lists deleted bucket {bucket}"
    _refused(lambda: s3.put_object(Bucket=bucket, Key="gone", Body=b"x"), ("NoSuchBucket",), 404, f"PutObject {bucket}",
             "The specified bucket does not exist")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
