"""batch-request-validation-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-request-validation-rejected"
GROUP = 'errors'
SERVICES = ['sqs']

EMPTY_BATCH = "AWS.SimpleQueueService.EmptyBatchRequest"
TOO_MANY_ENTRIES = "AWS.SimpleQueueService.TooManyEntriesInBatchRequest"
BATCH_IDS_NOT_DISTINCT = "AWS.SimpleQueueService.BatchEntryIdsNotDistinct"


def _err_code(fn):
    """Call fn() and return the botocore (Error.Code, Error.Message) it raises; an unexpected
    success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the batch to be rejected, but it SUCCEEDED: {result!r}")


def _assert_nothing_enqueued(sqs, url, *, reason):
    leftover = sqs.receive_message(
        QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2
    ).get("Messages", [])
    assert leftover == [], f"{reason}: expected nothing enqueued, got {len(leftover)} message(s)"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendMessageBatch rejects empty, over-10-entry and duplicate-Id batches with distinct codes and
    enqueues none of them, while a well-formed batch on the same queue still succeeds and delivers.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    code_empty = _err_code(lambda: sqs.send_message_batch(QueueUrl=url, Entries=[]))
    assert code_empty == (
        EMPTY_BATCH, "There should be at least one SendMessageBatchRequestEntry in the request."
    ), f"expected {EMPTY_BATCH}, got {code_empty}"
    _assert_nothing_enqueued(sqs, url, reason="empty batch")

    too_many = [{"Id": f"id{i}", "MessageBody": "x"} for i in range(11)]
    code_many = _err_code(lambda: sqs.send_message_batch(QueueUrl=url, Entries=too_many))
    assert code_many == (
        TOO_MANY_ENTRIES, "Maximum number of entries per request are 10. You have sent 11."
    ), f"expected {TOO_MANY_ENTRIES}, got {code_many}"
    _assert_nothing_enqueued(sqs, url, reason="11-entry batch")

    dup = [{"Id": "same", "MessageBody": "a"}, {"Id": "same", "MessageBody": "b"}]
    code_dup = _err_code(lambda: sqs.send_message_batch(QueueUrl=url, Entries=dup))
    assert code_dup == (BATCH_IDS_NOT_DISTINCT, "Id same repeated."), f"expected {BATCH_IDS_NOT_DISTINCT}, got {code_dup}"
    _assert_nothing_enqueued(sqs, url, reason="duplicate-id batch")

    # Positive control: the same queue still accepts and delivers a well-formed batch, so the
    # codes above are specific rejections, not a broken queue.
    valid = [{"Id": "ok-0", "MessageBody": "ok-0-body"}, {"Id": "ok-1", "MessageBody": "ok-1-body"}]
    resp = sqs.send_message_batch(QueueUrl=url, Entries=valid)
    assert not resp.get("Failed"), f"positive control failed: {resp.get('Failed')}"
    assert {e["Id"] for e in resp.get("Successful", [])} == {"ok-0", "ok-1"}, (
        f"expected both ok-0 and ok-1 to succeed, got {resp.get('Successful')}"
    )

    delivered = {}
    deadline = time.monotonic() + 20.0
    while len(delivered) < 2 and time.monotonic() < deadline:
        r = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=3)
        for msg in r.get("Messages", []):
            delivered[msg["Body"]] = msg["ReceiptHandle"]
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    if len(delivered) < 2:
        raise AssertionError(f"expected both positive-control messages delivered, got {sorted(delivered)}")
    assert set(delivered) == {"ok-0-body", "ok-1-body"}, (
        f"expected both positive-control messages delivered, got {sorted(delivered)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
