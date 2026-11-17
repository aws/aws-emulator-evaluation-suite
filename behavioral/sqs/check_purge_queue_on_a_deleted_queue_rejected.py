"""purge-queue-on-a-deleted-queue-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "purge-queue-on-a-deleted-queue-rejected"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PurgeQueue on a queue deleted earlier in the check is refused with NonExistentQueue
    after an independent read already reports the same queue gone, and a sibling queue still
    accepts PurgeQueue and empties."""
    sqs = ctx.client("sqs")
    base = ctx.unique_name("sim2real-behav-purgedel-")

    doomed = sqs.create_queue(QueueName=base + "-gone", tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_quietly(sqs, doomed))
    sibling = sqs.create_queue(QueueName=base + "-kept", tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_quietly(sqs, sibling))

    # Positive control: PurgeQueue on a live queue removes the message it holds.
    sqs.send_message(QueueUrl=sibling, MessageBody="purge-me")
    sqs.purge_queue(QueueUrl=sibling)
    deadline = time.monotonic() + _SETTLE_S
    left = None
    while time.monotonic() < deadline:
        left = sqs.receive_message(QueueUrl=sibling, MaxNumberOfMessages=10, WaitTimeSeconds=2).get(
            "Messages", []
        )
        if not left:
            break
    assert left == [], f"PurgeQueue on the live sibling left messages behind: {left!r}"

    sqs.delete_queue(QueueUrl=doomed)

    # Deletion is eventually consistent; poll an independent read (GetQueueAttributes, not
    # PurgeQueue) until it reports the queue gone, then hold PurgeQueue to the same refusal.
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

    purge_err = _error(lambda: sqs.purge_queue(QueueUrl=doomed))
    assert (purge_err.get("Code"), purge_err.get("Message")) == (_NOT_FOUND, _NOT_FOUND_MSG), (
        f"PurgeQueue on the deleted queue answered {purge_err!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
