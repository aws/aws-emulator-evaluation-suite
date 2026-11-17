"""single-message-operations-on-a-deleted-queue-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "single-message-operations-on-a-deleted-queue-rejected"
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


def _receive_one(sqs, url: str, *, body: str) -> str:
    """Send ``body`` and return the ReceiptHandle of its delivery."""
    sqs.send_message(QueueUrl=url, MessageBody=body)
    deadline = time.monotonic() + _SETTLE_S
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=3
        ).get("Messages", [])
        for m in msgs:
            if m.get("Body") == body:
                return m["ReceiptHandle"]
    raise AssertionError(f"never received the message {body!r} on {url!r} within {_SETTLE_S}s")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ChangeMessageVisibility and DeleteMessage with a receipt handle minted before the
    queue was deleted are each refused with NonExistentQueue once an independent read already
    reports the queue gone, while a sibling queue still accepts both calls on its own handle."""
    sqs = ctx.client("sqs")
    base = ctx.unique_name("sim2real-behav-msgdel-")

    sibling = sqs.create_queue(QueueName=base + "-kept", tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_quietly(sqs, sibling))
    doomed = sqs.create_queue(QueueName=base + "-gone", tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_quietly(sqs, doomed))

    # Positive control: both calls succeed on a live queue, using a receipt handle minted
    # the same way as the doomed queue's.
    control_receipt = _receive_one(sqs, sibling, body="control")
    sqs.change_message_visibility(QueueUrl=sibling, ReceiptHandle=control_receipt, VisibilityTimeout=5)
    sqs.delete_message(QueueUrl=sibling, ReceiptHandle=control_receipt)
    deadline = time.monotonic() + _SETTLE_S
    left = None
    while time.monotonic() < deadline:
        left = sqs.receive_message(QueueUrl=sibling, MaxNumberOfMessages=10, WaitTimeSeconds=3).get(
            "Messages", []
        )
        if not left:
            break
    assert left == [], f"positive control DeleteMessage left messages behind: {left!r}"

    doomed_receipt = _receive_one(sqs, doomed, body="doomed")
    sqs.delete_queue(QueueUrl=doomed)

    # Deletion is eventually consistent; poll an independent read (GetQueueAttributes, not
    # ChangeMessageVisibility/DeleteMessage) until it reports the queue gone, then hold both
    # single-message operations to the same refusal on the handle minted before the delete.
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
        lambda: sqs.change_message_visibility(
            QueueUrl=doomed, ReceiptHandle=doomed_receipt, VisibilityTimeout=5
        )
    )
    assert (vis_err.get("Code"), vis_err.get("Message")) == (_NOT_FOUND, _NOT_FOUND_MSG), (
        f"ChangeMessageVisibility on the deleted queue answered {vis_err!r}"
    )

    del_err = _error(lambda: sqs.delete_message(QueueUrl=doomed, ReceiptHandle=doomed_receipt))
    assert (del_err.get("Code"), del_err.get("Message")) == (_NOT_FOUND, _NOT_FOUND_MSG), (
        f"DeleteMessage on the deleted queue answered {del_err!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
