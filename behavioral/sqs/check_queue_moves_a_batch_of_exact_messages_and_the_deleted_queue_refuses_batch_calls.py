"""queue-moves-a-batch-of-exact-messages-and-the-deleted-queue-refuses-batch-calls."""

from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "queue-moves-a-batch-of-exact-messages-and-the-deleted-queue-refuses-batch-calls"
GROUP = "state"
SERVICES = ["sqs"]

QUEUE_NOT_FOUND = "AWS.SimpleQueueService.NonExistentQueue"
QUEUE_NOT_FOUND_MSG = "The specified queue does not exist."
# A deleted queue can keep answering for a while and the counters converge asynchronously.
GONE_WAIT_S = 40.0
DRAIN_WAIT_S = 40.0
RECEIVE_WAIT_S = 40.0

# Three bodies of different sizes and alphabets, so no one length or content can be assumed.
_BODIES = {
    "e0": "z",
    "e1": "Grüße-" * 171,
    "e2": "0123456789abcdef" * 4096,
}


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


def _error(fn, what):
    """The NonExistentQueue error response of one call; any other outcome fails."""
    try:
        fn()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == QUEUE_NOT_FOUND, f"{what}: expected {QUEUE_NOT_FOUND}, got {code!r}"
        return exc.response
    raise AssertionError(f"{what}: expected {QUEUE_NOT_FOUND}, the call succeeded")


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
    """SendMessageBatch, ReceiveMessage and DeleteMessageBatch move three differently sized messages
    byte-exact (per-entry MD5 and MessageId) and drain the queue; once deleted, the queue reads
    NonExistentQueue, leaves the listing and refuses SendMessageBatch and DeleteMessageBatch.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SendMessageBatch.html
    """
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-")
    url = sqs.create_queue(QueueName=name, Attributes={"VisibilityTimeout": "120"})["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_queue_if_present(sqs, url))

    sent = sqs.send_message_batch(
        QueueUrl=url, Entries=[{"Id": i, "MessageBody": b} for i, b in _BODIES.items()]
    )
    assert sent.get("Failed", []) == [], f"SendMessageBatch failed entries: {sent.get('Failed')!r}"
    by_id = {e["Id"]: e for e in sent["Successful"]}
    assert sorted(by_id) == sorted(_BODIES), (
        f"SendMessageBatch succeeded ids {sorted(by_id)}, expected {sorted(_BODIES)}"
    )
    md5 = {i: hashlib.md5(b.encode("utf-8")).hexdigest() for i, b in _BODIES.items()}
    for i, entry in by_id.items():
        assert entry["MD5OfMessageBody"] == md5[i], (
            f"entry {i} MD5OfMessageBody {entry['MD5OfMessageBody']!r}, expected {md5[i]!r}"
        )
    want = {by_id[i]["MessageId"]: i for i in _BODIES}

    got: dict[str, dict] = {}
    deadline = time.monotonic() + RECEIVE_WAIT_S
    while len(got) < len(want) and time.monotonic() < deadline:
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5).get(
            "Messages", []
        ):
            got[m["MessageId"]] = m
    assert sorted(got) == sorted(want), (
        f"received {len(got)} distinct MessageIds, expected exactly the {len(want)} the batch returned"
    )
    for mid, m in got.items():
        i = want[mid]
        assert m["Body"] == _BODIES[i], (
            f"message {i} arrived with a {len(m['Body'])}-char body, sent {len(_BODIES[i])} chars"
        )
        assert m["MD5OfBody"] == md5[i], (
            f"message {i} MD5OfBody {m['MD5OfBody']!r}, expected {md5[i]!r}"
        )

    handles = [{"Id": want[mid], "ReceiptHandle": m["ReceiptHandle"]} for mid, m in got.items()]
    deleted = sqs.delete_message_batch(QueueUrl=url, Entries=handles)
    assert deleted.get("Failed", []) == [], (
        f"DeleteMessageBatch failed entries: {deleted.get('Failed')!r}"
    )
    assert sorted(e["Id"] for e in deleted["Successful"]) == sorted(_BODIES), (
        f"DeleteMessageBatch succeeded ids {deleted['Successful']!r}, expected {sorted(_BODIES)}"
    )
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
    # The read-only GetQueueAttributes establishes the deletion; the batch calls are then graded once.
    read = _poll_until_code(
        lambda: sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"]),
        QUEUE_NOT_FOUND,
        timeout_s=GONE_WAIT_S,
        interval_s=5,
        what="GetQueueAttributes on the deleted queue",
    )
    _assert_not_found(read, "GetQueueAttributes on the deleted queue")
    _poll_until(
        lambda: _list_urls(sqs, name),
        lambda urls: url not in urls,
        timeout_s=GONE_WAIT_S,
        interval_s=5,
        description="the deleted queue leaving ListQueues",
    )
    dead_send = _error(
        lambda: sqs.send_message_batch(
            QueueUrl=url, Entries=[{"Id": "late", "MessageBody": "after-delete"}]
        ),
        "SendMessageBatch on the deleted queue",
    )
    _assert_not_found(dead_send, "SendMessageBatch on the deleted queue")
    dead_delete = _error(
        lambda: sqs.delete_message_batch(QueueUrl=url, Entries=handles),
        "DeleteMessageBatch on the deleted queue",
    )
    _assert_not_found(dead_delete, "DeleteMessageBatch on the deleted queue")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
