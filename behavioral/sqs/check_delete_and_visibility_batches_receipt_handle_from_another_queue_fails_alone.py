"""delete-and-visibility-batches-receipt-handle-from-another-queue-fails-alone."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-and-visibility-batches-receipt-handle-from-another-queue-fails-alone"
GROUP = "batch"
SERVICES = ["sqs"]

_TAGS = {"sim2real": "delete-and-visibility-batches-receipt-handle-from-another-queue-fails-alone"}
_ERR_HANDLE = "ReceiptHandleIsInvalid"


def _handle_reason(handle: str) -> str:
    """Message AWS returns for a well-formed handle scoped to a different queue."""
    return f'The receipt handle "{handle}" is not valid for this queue.'


def _receive_one(sqs, url, *, visibility_timeout, timeout_s=20.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2,
            VisibilityTimeout=visibility_timeout,
        ).get("Messages", [])
        if msgs:
            return msgs[0]
    raise AssertionError(f"no message receivable on {url!r} within {timeout_s}s")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A batch entry whose receipt handle was minted by another queue fails alone with
    ReceiptHandleIsInvalid and a queue-scoped message, distinct from the malformed-handle message;
    the sibling entry with a local handle succeeds and the foreign queue's message is untouched.
    """
    sqs = ctx.client("sqs")
    url_a = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-crossq-a-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url_a))
    url_b = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-crossq-b-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url_b))

    sqs.send_message(QueueUrl=url_b, MessageBody="minted-on-b")
    foreign = _receive_one(sqs, url_b, visibility_timeout=120)
    foreign_handle = foreign["ReceiptHandle"]

    # --- DeleteMessageBatch: the foreign handle fails alone, the local one is really deleted.
    sqs.send_message(QueueUrl=url_a, MessageBody="delete-me-on-a")
    local_for_delete = _receive_one(sqs, url_a, visibility_timeout=120)

    resp = sqs.delete_message_batch(QueueUrl=url_a, Entries=[
        {"Id": "local", "ReceiptHandle": local_for_delete["ReceiptHandle"]},
        {"Id": "foreign", "ReceiptHandle": foreign_handle},
    ])
    ok = {e["Id"] for e in resp.get("Successful", [])}
    failed = {e["Id"]: e for e in resp.get("Failed", [])}
    assert ok == {"local"}, f"DeleteMessageBatch Successful Ids were {ok!r}, expected just 'local'"
    assert set(failed) == {"foreign"}, f"DeleteMessageBatch Failed Ids were {set(failed)!r}"
    assert failed["foreign"].get("Code") == _ERR_HANDLE, (
        f"foreign-handle Delete entry Code was {failed['foreign'].get('Code')!r}"
    )
    assert failed["foreign"].get("Message") == _handle_reason(foreign_handle), (
        f"foreign-handle Delete entry Message was {failed['foreign'].get('Message')!r}"
    )
    assert failed["foreign"].get("SenderFault") is True, (
        f"foreign-handle Delete entry SenderFault was {failed['foreign'].get('SenderFault')!r}"
    )
    gone = sqs.receive_message(QueueUrl=url_a, MaxNumberOfMessages=10, WaitTimeSeconds=3)
    assert gone.get("Messages", []) == [], (
        f"after the batch, url_a still held {[m['Body'] for m in gone.get('Messages', [])]!r}; "
        f"the local entry's delete must really have taken effect"
    )

    # --- ChangeMessageVisibilityBatch: the foreign handle fails alone, the local one is released.
    sqs.send_message(QueueUrl=url_a, MessageBody="release-me-on-a")
    local_for_cmv = _receive_one(sqs, url_a, visibility_timeout=120)

    resp = sqs.change_message_visibility_batch(QueueUrl=url_a, Entries=[
        {"Id": "local", "ReceiptHandle": local_for_cmv["ReceiptHandle"], "VisibilityTimeout": 0},
        {"Id": "foreign", "ReceiptHandle": foreign_handle, "VisibilityTimeout": 0},
    ])
    ok = {e["Id"] for e in resp.get("Successful", [])}
    failed = {e["Id"]: e for e in resp.get("Failed", [])}
    assert ok == {"local"}, f"CMV batch Successful Ids were {ok!r}, expected just 'local'"
    assert set(failed) == {"foreign"}, f"CMV batch Failed Ids were {set(failed)!r}"
    assert failed["foreign"].get("Code") == _ERR_HANDLE, (
        f"foreign-handle CMV entry Code was {failed['foreign'].get('Code')!r}"
    )
    assert failed["foreign"].get("Message") == _handle_reason(foreign_handle), (
        f"foreign-handle CMV entry Message was {failed['foreign'].get('Message')!r}"
    )
    released = sqs.receive_message(QueueUrl=url_a, MaxNumberOfMessages=10, WaitTimeSeconds=3)
    released_bodies = [m["Body"] for m in released.get("Messages", [])]
    assert released_bodies == ["release-me-on-a"], (
        f"after the batch, an immediate receive on url_a returned {released_bodies!r}; the "
        f"local entry's VisibilityTimeout=0 must really have released the message"
    )
    sqs.delete_message(QueueUrl=url_a, ReceiptHandle=released["Messages"][0]["ReceiptHandle"])

    # The foreign message on url_b was never touched by either refused entry.
    still_there = sqs.receive_message(QueueUrl=url_b, MaxNumberOfMessages=10, WaitTimeSeconds=3)
    assert [m["Body"] for m in still_there.get("Messages", [])] == [], (
        f"url_b answered {[m['Body'] for m in still_there.get('Messages', [])]!r} to an "
        f"immediate receive; its message is still in flight under foreign_handle and must not "
        f"have been affected by either refused batch entry"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
