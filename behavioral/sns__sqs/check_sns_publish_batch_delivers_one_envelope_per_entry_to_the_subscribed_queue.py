"""sns-publish-batch-delivers-one-envelope-per-entry-to-the-subscribed-queue."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sns-publish-batch-delivers-one-envelope-per-entry-to-the-subscribed-queue"

GROUP = "event-propagation"

SERVICES = ["sns", "sqs"]

# Entry id -> (message, subject or None); bodies and subjects differ so no entry can stand in for another.
_ENTRIES = {
    "first": ("one", "Subject one"),
    "second": ('{"n": 2, "text": "zwei 二"}', None),
    "third": ("drei-" * 300, "Dritter Betreff"),
}


def _allow_topic(ctx, queue: dict, topic_arn: str) -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue["arn"],
                "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
            }
        ],
    }
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)}
    )


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A three-entry PublishBatch reaches the subscribed queue as three Notification envelopes, each
    carrying the MessageId PublishBatch returned for its entry, that entry's exact Message, its
    Subject where one was given (none otherwise) and the TopicArn.
    """
    topic = _create_topic(ctx)
    queue = _create_queue(ctx)
    _allow_topic(ctx, queue, topic["arn"])
    sns = ctx.client("sns")
    sub_arn = sns.subscribe(
        TopicArn=topic["arn"], Protocol="sqs", Endpoint=queue["arn"], ReturnSubscriptionArn=True
    )["SubscriptionArn"]
    ctx.on_cleanup(
        _tolerant(lambda: ctx.client("sns").unsubscribe(SubscriptionArn=sub_arn), "NotFound")
    )

    request = []
    for entry_id, (message, subject) in _ENTRIES.items():
        entry: dict[str, Any] = {"Id": entry_id, "Message": message}
        if subject:
            entry["Subject"] = subject
        request.append(entry)
    resp = sns.publish_batch(TopicArn=topic["arn"], PublishBatchRequestEntries=request)
    assert resp.get("Failed", []) == [], f"PublishBatch failed entries: {resp.get('Failed')!r}"
    ids = {e["Id"]: e["MessageId"] for e in resp["Successful"]}
    assert sorted(ids) == sorted(_ENTRIES), (
        f"PublishBatch succeeded ids {sorted(ids)}, expected {sorted(_ENTRIES)}"
    )
    assert len(set(ids.values())) == len(ids), f"PublishBatch returned repeated MessageIds: {ids!r}"

    # Delivery is at least once: envelopes are deduplicated by their MessageId, and a stray is an
    # envelope whose MessageId PublishBatch never returned.
    sqs = ctx.client("sqs")
    envelopes: dict = {}
    strays: list = []
    deadline = time.monotonic() + 40.0
    final_poll = False
    while True:
        resp = sqs.receive_message(QueueUrl=queue["url"], MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            mid = body.get("MessageId") if isinstance(body, dict) else None
            if mid in ids.values():
                envelopes.setdefault(mid, body)
            else:
                strays.append(body)
            sqs.delete_message(QueueUrl=queue["url"], ReceiptHandle=msg["ReceiptHandle"])
        if final_poll:
            break
        if set(envelopes) == set(ids.values()):
            final_poll = True  # one more receive catches a stray landing beside the last entry
        elif time.monotonic() >= deadline:
            raise AssertionError(
                f"{len(envelopes)} of {len(ids)} entries' envelopes arrived within 40s; strays {strays!r:.300}"
            )
    assert not strays, f"the queue received envelopes PublishBatch never returned: {strays!r:.300}"
    for entry_id, (message, subject) in _ENTRIES.items():
        env = envelopes[ids[entry_id]]
        got = (env.get("Type"), env.get("TopicArn"), env.get("Message"), env.get("Subject"))
        want = ("Notification", topic["arn"], message, subject)
        assert got == want, (
            f"entry {entry_id}: envelope (Type, TopicArn, Message, Subject) {got!r}, expected {want!r}"
        )
    _gone_subscription(ctx, sub_arn, topic["arn"])
    _gone_topic(ctx, topic["arn"])
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


def _create_queue(ctx, fifo: bool = False, **attrs: str) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    base = _xname(ctx, "q")
    name = f"{base}.fifo" if fifo else base
    sqs = ctx.client("sqs")
    create_attrs = dict(attrs)
    if fifo:
        create_attrs["FifoQueue"] = "true"
    resp = sqs.create_queue(QueueName=name, Attributes=create_attrs, tags=_xsvc_resource_tags())
    url = resp["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    ctx.on_cleanup(_tolerant(lambda: sqs.delete_queue(QueueUrl=url), *_SQS_NF))
    return {"name": name, "url": url, "arn": arn}


def _create_topic(ctx) -> dict[str, str]:
    """Create an SNS topic (registers delete_topic teardown). Returns {name,arn}."""
    name = _xname(ctx, "topic")
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=name, Tags=_xsvc_tags_kv())["TopicArn"]
    ctx.on_cleanup(_tolerant(lambda: sns.delete_topic(TopicArn=arn), "NotFound"))
    return {"name": name, "arn": arn}


#: Bounded convergence for a delete to reach its terminal not-found answer (the default service
#: class budget); a deadline, never an assertion on elapsed time.
_GONE_S = 40.0


def _err(exc: ClientError) -> tuple[str, int, str]:
    """(code, HTTP status, message) of a ClientError."""
    e = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return e.get("Code") or "", status, e.get("Message") or e.get("message") or ""


def _refused(fn, codes: tuple[str, ...], status: int, what: str, message: str) -> None:
    """``fn()`` must fail with one of ``codes`` in the HTTP class of ``status``, with exactly ``message``."""
    try:
        fn()
    except ClientError as exc:
        code, got, msg = _err(exc)
        in_class = isinstance(got, int) and got // 100 == status // 100
        assert code in codes and in_class, (
            f"{what}: expected {'/'.join(codes)} HTTP {status // 100}xx, got {code!r} HTTP {got!r}: {msg[:150]!r}"
        )
        assert msg == message, f"{what}: {code} message is {msg[:200]!r}, expected {message!r}"
        return
    raise AssertionError(f"{what}: expected {'/'.join(codes)} HTTP {status}, the call succeeded")


def _poll_refused(fn, codes, status, what, message: str, timeout_s: float = _GONE_S) -> None:
    """Poll ``fn`` until it reaches the terminal not-found answer, then grade it with ``_refused``.

    A success while the delete converges is retried; any other error fails at once.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            last = fn()
        except ClientError as exc:
            code, _, _ = _err(exc)
            if code in codes:
                _refused(fn, codes, status, what, message)
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{what}: still readable {timeout_s:.0f}s after the delete; last answer {last!r:.300}"
            )
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


def _gone_queue(ctx, name: str, url: str) -> None:
    sqs = ctx.client("sqs")
    sqs.delete_queue(QueueUrl=url)
    # A deleted queue can keep answering for a while, so the read is polled.
    _poll_refused(
        lambda: sqs.get_queue_url(QueueName=name), _SQS_NF, 400, f"GetQueueUrl {name}", _SQS_NF_MSG
    )
    listed = sqs.list_queues(QueueNamePrefix=name).get("QueueUrls", [])
    assert not [u for u in listed if u.rstrip("/").split("/")[-1] == name], (
        f"ListQueues still lists deleted queue {name}"
    )
    _refused(
        lambda: sqs.send_message(QueueUrl=url, MessageBody="gone"),
        _SQS_NF,
        400,
        f"SendMessage {name}",
        _SQS_NF_MSG,
    )


def _gone_topic(ctx, arn: str) -> None:
    sns = ctx.client("sns")
    sns.delete_topic(TopicArn=arn)
    nf = ("NotFound",)
    _poll_refused(
        lambda: sns.get_topic_attributes(TopicArn=arn),
        nf,
        404,
        "GetTopicAttributes",
        "Topic does not exist",
    )
    listed = {t["TopicArn"] for t in _paged(sns, "list_topics", "Topics")}
    assert arn not in listed, "ListTopics still lists the deleted topic"
    _refused(
        lambda: sns.publish(TopicArn=arn, Message="gone"),
        nf,
        404,
        "Publish to deleted topic",
        "Topic does not exist",
    )


def _gone_subscription(ctx, sub_arn: str, topic_arn: str) -> None:
    sns = ctx.client("sns")
    sns.unsubscribe(SubscriptionArn=sub_arn)
    nf = ("NotFound",)
    _poll_refused(
        lambda: sns.get_subscription_attributes(SubscriptionArn=sub_arn),
        nf,
        404,
        "GetSubscriptionAttributes",
        "Subscription does not exist",
    )
    listed = {
        s["SubscriptionArn"]
        for s in _paged(sns, "list_subscriptions_by_topic", "Subscriptions", TopicArn=topic_arn)
    }
    assert sub_arn not in listed, "ListSubscriptionsByTopic still lists the removed subscription"
    _refused(
        lambda: sns.set_subscription_attributes(
            SubscriptionArn=sub_arn, AttributeName="RawMessageDelivery", AttributeValue="true"
        ),
        nf,
        404,
        "SetSubscriptionAttributes on removed subscription",
        "Subscription does not exist",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
