"""fifo-queue-moves-an-exact-multibyte-message-and-the-deleted-fifo-queue-is-gone."""

from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fifo-queue-moves-an-exact-multibyte-message-and-the-deleted-fifo-queue-is-gone"
GROUP = "state"
SERVICES = ["sqs"]

QUEUE_NOT_FOUND = "AWS.SimpleQueueService.NonExistentQueue"
QUEUE_NOT_FOUND_MSG = "The specified queue does not exist."
# A deleted queue can keep answering for a while and the counters converge asynchronously.
GONE_WAIT_S = 40.0
DRAIN_WAIT_S = 40.0
RECEIVE_WAIT_S = 40.0

# Tab, LF, CR, Latin-1, BMP CJK, a private-use char and astral emoji: every range SQS admits.
_PIECE = "\tline\nnext\räß€中文�\U0001f600\U0010fffd|"


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not observed within {timeout_s:.0f}s; last saw {last!r}"
            )
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


def _assert_not_found(response, what):
    """HTTP 400 with the exact NonExistentQueue message."""
    status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert status == 400, f"{what} answered HTTP {status!r}, expected 400"
    message = response["Error"].get("Message")
    assert message == QUEUE_NOT_FOUND_MSG, (
        f"{what} answered message {message!r}, expected {QUEUE_NOT_FOUND_MSG!r}"
    )


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
    """A FIFO queue moves one multibyte message spanning every admitted character range byte-exact
    (MD5 of its UTF-8, MessageId, SequenceNumber, group and dedup ids), then the deleted FIFO queue
    is gone: GetQueueUrl by name and ReceiveMessage on its URL answer NonExistentQueue.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SendMessage.html
    """
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-") + ".fifo"
    url = sqs.create_queue(
        QueueName=name, Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "false"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_queue_if_present(sqs, url))

    body = _PIECE * 97
    group = "grp-" + name[-12:-5]
    dedup = "dd-" + hashlib.sha256(body.encode("utf-8")).hexdigest()[:40]
    sent = sqs.send_message(
        QueueUrl=url, MessageBody=body, MessageGroupId=group, MessageDeduplicationId=dedup
    )
    want_md5 = hashlib.md5(body.encode("utf-8")).hexdigest()
    assert sent["MD5OfMessageBody"] == want_md5, (
        f"SendMessage MD5OfMessageBody {sent['MD5OfMessageBody']!r}, expected the MD5 of the UTF-8 body {want_md5!r}"
    )
    received = _poll_until(
        lambda: sqs.receive_message(
            QueueUrl=url,
            MaxNumberOfMessages=1,
            WaitTimeSeconds=5,
            MessageSystemAttributeNames=[
                "MessageGroupId",
                "MessageDeduplicationId",
                "SequenceNumber",
            ],
        ).get("Messages", []),
        lambda msgs: len(msgs) == 1,
        timeout_s=RECEIVE_WAIT_S,
        interval_s=1,
        description="the sent message being received",
    )
    msg = received[0]
    assert msg["Body"] == body, (
        f"received body of {len(msg['Body'])} chars differs from the {len(body)}-char body sent"
    )
    assert msg["MD5OfBody"] == want_md5, f"MD5OfBody {msg['MD5OfBody']!r}, expected {want_md5!r}"
    assert msg["MessageId"] == sent["MessageId"], (
        f"received MessageId {msg['MessageId']!r}, SendMessage returned {sent['MessageId']!r}"
    )
    attrs = msg["Attributes"]
    got = (
        attrs.get("MessageGroupId"),
        attrs.get("MessageDeduplicationId"),
        attrs.get("SequenceNumber"),
    )
    want = (group, dedup, sent["SequenceNumber"])
    assert got == want, (
        f"(MessageGroupId, MessageDeduplicationId, SequenceNumber) received {got!r}, expected {want!r}"
    )

    sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    _poll_until(
        lambda: sqs.get_queue_attributes(
            QueueUrl=url,
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"],
        lambda a: (
            a.get("ApproximateNumberOfMessages") == "0"
            and a.get("ApproximateNumberOfMessagesNotVisible") == "0"
        ),
        timeout_s=DRAIN_WAIT_S,
        interval_s=2,
        description="the queue counters draining to 0",
    )

    sqs.delete_queue(QueueUrl=url)
    by_name = _poll_until_code(
        lambda: sqs.get_queue_url(QueueName=name),
        QUEUE_NOT_FOUND,
        timeout_s=GONE_WAIT_S,
        interval_s=5,
        what="GetQueueUrl for the deleted FIFO queue",
    )
    _assert_not_found(by_name, "GetQueueUrl for the deleted FIFO queue")
    _poll_until(
        lambda: _list_urls(sqs, name[:-5]),
        lambda urls: url not in urls,
        timeout_s=GONE_WAIT_S,
        interval_s=5,
        description="the deleted FIFO queue leaving ListQueues",
    )
    dead_receive = _poll_until_code(
        lambda: sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=0),
        QUEUE_NOT_FOUND,
        timeout_s=GONE_WAIT_S,
        interval_s=5,
        what="ReceiveMessage on the deleted FIFO queue",
    )
    _assert_not_found(dead_receive, "ReceiveMessage on the deleted FIFO queue")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
