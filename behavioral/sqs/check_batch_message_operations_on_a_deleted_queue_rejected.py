"""batch-message-operations-on-a-deleted-queue-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-message-operations-on-a-deleted-queue-rejected"
GROUP = "lifecycle"
SERVICES = ["sqs"]

_NOT_FOUND = "AWS.SimpleQueueService.NonExistentQueue"
_NOT_FOUND_MSG = "The specified queue does not exist."
_SETTLE_S = 60.0


def _error(fn) -> dict:
    """The botocore Error dict ``fn`` raises. An unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _delete_quietly(sqs, url: str) -> None:
    try:
        sqs.delete_queue(QueueUrl=url)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != _NOT_FOUND:
            raise


def _receive_two(sqs, url: str, *, prefix: str) -> list[str]:
    """Send two messages and return the ReceiptHandles of both deliveries."""
    bodies = {f"{prefix}-0", f"{prefix}-1"}
    for body in bodies:
        sqs.send_message(QueueUrl=url, MessageBody=body)
    receipts: dict[str, str] = {}
    deadline = time.monotonic() + _SETTLE_S
    while len(receipts) < len(bodies) and time.monotonic() < deadline:
        msgs = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=3
        ).get("Messages", [])
        for m in msgs:
            if m.get("Body") in bodies:
                receipts[m["Body"]] = m["ReceiptHandle"]
    assert len(receipts) == len(bodies), (
        f"only received {sorted(receipts)} of {sorted(bodies)} on {url!r} within {_SETTLE_S}s"
    )
    return list(receipts.values())


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ChangeMessageVisibilityBatch and DeleteMessageBatch, built from receipt handles minted
    before the queue was deleted, are each refused with NonExistentQueue once an independent
    read already reports the queue gone, while a sibling queue still accepts both batch calls."""
    sqs = ctx.client("sqs")
    base = ctx.unique_name("sim2real-behav-batchdel-")

    sibling = sqs.create_queue(QueueName=base + "-kept", tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_quietly(sqs, sibling))
    doomed = sqs.create_queue(QueueName=base + "-gone", tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_quietly(sqs, doomed))

    # Positive control: both batch calls succeed on a live queue.
    control_receipts = _receive_two(sqs, sibling, prefix="control")
    vis_resp = sqs.change_message_visibility_batch(
        QueueUrl=sibling,
        Entries=[
            {"Id": f"c{i}", "ReceiptHandle": r, "VisibilityTimeout": 5}
            for i, r in enumerate(control_receipts)
        ],
    )
    assert not vis_resp.get("Failed"), (
        f"positive control ChangeMessageVisibilityBatch failed entries: {vis_resp.get('Failed')!r}"
    )
    del_resp = sqs.delete_message_batch(
        QueueUrl=sibling,
        Entries=[{"Id": f"d{i}", "ReceiptHandle": r} for i, r in enumerate(control_receipts)],
    )
    assert not del_resp.get("Failed"), (
        f"positive control DeleteMessageBatch failed entries: {del_resp.get('Failed')!r}"
    )
    deadline = time.monotonic() + _SETTLE_S
    left = None
    while time.monotonic() < deadline:
        left = sqs.receive_message(QueueUrl=sibling, MaxNumberOfMessages=10, WaitTimeSeconds=3).get(
            "Messages", []
        )
        if not left:
            break
    assert left == [], f"positive control DeleteMessageBatch left messages behind: {left!r}"

    doomed_receipts = _receive_two(sqs, doomed, prefix="doomed")
    sqs.delete_queue(QueueUrl=doomed)

    # Deletion is eventually consistent; poll an independent read (GetQueueAttributes, not the
    # batch operations) until it reports the queue gone, then hold both batch calls to the same
    # refusal on handles minted before the delete.
    read_err: dict = {}
    deadline = time.monotonic() + _SETTLE_S
    while time.monotonic() < deadline:
        try:
            sqs.get_queue_attributes(QueueUrl=doomed, AttributeNames=["QueueArn"])
        except ClientError as exc:
            read_err = exc.response.get("Error", {})
            break
        time.sleep(3)
    assert (read_err.get("Code"), read_err.get("Message")) == (_NOT_FOUND, _NOT_FOUND_MSG), (
        f"GetQueueAttributes on the deleted queue answered {read_err!r} within {_SETTLE_S}s"
    )

    vis_err = _error(
        lambda: sqs.change_message_visibility_batch(
            QueueUrl=doomed,
            Entries=[
                {"Id": f"v{i}", "ReceiptHandle": r, "VisibilityTimeout": 5}
                for i, r in enumerate(doomed_receipts)
            ],
        )
    )
    assert (vis_err.get("Code"), vis_err.get("Message")) == (_NOT_FOUND, _NOT_FOUND_MSG), (
        f"ChangeMessageVisibilityBatch on the deleted queue answered {vis_err!r}"
    )

    del_err = _error(
        lambda: sqs.delete_message_batch(
            QueueUrl=doomed,
            Entries=[{"Id": f"x{i}", "ReceiptHandle": r} for i, r in enumerate(doomed_receipts)],
        )
    )
    assert (del_err.get("Code"), del_err.get("Message")) == (_NOT_FOUND, _NOT_FOUND_MSG), (
        f"DeleteMessageBatch on the deleted queue answered {del_err!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
