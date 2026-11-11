"""queue-moves-an-exact-message-and-the-deleted-queue-is-gone."""

from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "queue-moves-an-exact-message-and-the-deleted-queue-is-gone"
GROUP = "state"
SERVICES = ["sqs"]

QUEUE_NOT_FOUND = "AWS.SimpleQueueService.NonExistentQueue"
# DeleteQueue is documented to take up to 60 s to propagate; the counters converge asynchronously.
GONE_WAIT_S = 240.0
DRAIN_WAIT_S = 120.0
RECEIVE_WAIT_S = 60.0


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not observed within {timeout_s:.0f}s; last saw {last!r}")
        time.sleep(interval_s)


def _poll_until_code(fn, code, *, timeout_s, interval_s, what):
    """Poll fn until it fails with code; return that error response. FAILS on the deadline."""
    deadline = time.monotonic() + timeout_s
    seen = "<call succeeded>"
    while True:
        try:
            fn()
            seen = "<call succeeded>"
        except ClientError as exc:
            seen = exc.response["Error"]["Code"]
            if seen == code:
                return exc.response
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: expected {code}, got {seen!r} after {timeout_s:.0f}s")
        time.sleep(interval_s)


def _assert_refusal(response, what):
    status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert isinstance(status, int) and 400 <= status < 500, f"{what} answered HTTP {status!r}, expected 4xx"
    assert response["Error"].get("Message"), f"{what} answered an empty error message"


def _list_urls(sqs, prefix):
    urls, token = [], None
    while True:
        page = sqs.list_queues(QueueNamePrefix=prefix, **({"NextToken": token} if token else {}))
        urls.extend(page.get("QueueUrls", []))
        token = page.get("NextToken")
        if not token:
            return urls


def _delete_queue_if_present(sqs, url):
    try:
        sqs.delete_queue(QueueUrl=url)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != QUEUE_NOT_FOUND:
            raise


@tags("axis:happy-path", "cap:c1", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A queue moves one exact message (sent, received byte-exact with its MD5 and MessageId,
    deleted, drained), then the deleted queue is gone: read by URL answers NonExistentQueue,
    the listing filtered to its name drops it, and SendMessage on the dead URL is refused."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-")
    url = sqs.create_queue(QueueName=name)["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_queue_if_present(sqs, url))

    body = "move-me-exactly"
    sent = sqs.send_message(QueueUrl=url, MessageBody=body)
    received = _poll_until(
        lambda: sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=5).get(
            "Messages", []
        ),
        lambda msgs: len(msgs) == 1,
        timeout_s=RECEIVE_WAIT_S,
        interval_s=1,
        description="the sent message being received",
    )
    msg = received[0]
    assert msg["Body"] == body, f"received body {msg['Body']!r}, sent {body!r}"
    assert msg["MD5OfBody"] == hashlib.md5(body.encode()).hexdigest(), (
        f"MD5OfBody {msg['MD5OfBody']!r} is not the MD5 of the sent body"
    )
    assert msg["MessageId"] == sent["MessageId"], (
        f"received MessageId {msg['MessageId']!r}, SendMessage returned {sent['MessageId']!r}"
    )
    sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    # A message that was not deleted stays counted, in flight or visible again, so the poll fails.
    _poll_until(
        lambda: sqs.get_queue_attributes(
            QueueUrl=url,
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"],
        lambda a: a.get("ApproximateNumberOfMessages") == "0"
        and a.get("ApproximateNumberOfMessagesNotVisible") == "0",
        timeout_s=DRAIN_WAIT_S,
        interval_s=2,
        description="the queue counters draining to 0",
    )

    sqs.delete_queue(QueueUrl=url)
    read = _poll_until_code(
        lambda: sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"]),
        QUEUE_NOT_FOUND,
        timeout_s=GONE_WAIT_S,
        interval_s=10,
        what="GetQueueAttributes on the deleted queue",
    )
    _assert_refusal(read, "GetQueueAttributes on the deleted queue")
    _poll_until(
        lambda: _list_urls(sqs, name),
        lambda urls: url not in urls,
        timeout_s=GONE_WAIT_S,
        interval_s=10,
        description="the deleted queue leaving ListQueues",
    )
    dead_send = _poll_until_code(
        lambda: sqs.send_message(QueueUrl=url, MessageBody="after-delete"),
        QUEUE_NOT_FOUND,
        timeout_s=GONE_WAIT_S,
        interval_s=10,
        what="SendMessage on the deleted queue",
    )
    _assert_refusal(dead_send, "SendMessage on the deleted queue")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
