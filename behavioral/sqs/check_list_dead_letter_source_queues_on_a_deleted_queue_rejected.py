"""list-dead-letter-source-queues-on-a-deleted-queue-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-dead-letter-source-queues-on-a-deleted-queue-rejected"
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
    """ListDeadLetterSourceQueues on a dead-letter queue deleted earlier in the check is
    refused with NonExistentQueue after an independent read already reports it gone, while a
    sibling dead-letter queue still lists the source wired to it."""
    sqs = ctx.client("sqs")
    base = ctx.unique_name("sim2real-behav-dlqlist-")

    doomed_dlq = sqs.create_queue(QueueName=base + "-dlq-gone", tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_quietly(sqs, doomed_dlq))
    src_for_doomed = sqs.create_queue(QueueName=base + "-src-gone", tags={"sim2real": CHECK})[
        "QueueUrl"
    ]
    ctx.on_cleanup(lambda: _delete_quietly(sqs, src_for_doomed))

    kept_dlq = sqs.create_queue(QueueName=base + "-dlq-kept", tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_quietly(sqs, kept_dlq))
    src_for_kept = sqs.create_queue(QueueName=base + "-src-kept", tags={"sim2real": CHECK})[
        "QueueUrl"
    ]
    ctx.on_cleanup(lambda: _delete_quietly(sqs, src_for_kept))

    def _wire(src_url: str, dlq_url: str) -> None:
        dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["QueueArn"])[
            "Attributes"
        ]["QueueArn"]
        sqs.set_queue_attributes(
            QueueUrl=src_url,
            Attributes={
                "RedrivePolicy": json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 5})
            },
        )

    _wire(src_for_doomed, doomed_dlq)
    _wire(src_for_kept, kept_dlq)

    # Positive control: the kept dead-letter queue's sources list the source wired to it.
    deadline = time.monotonic() + _SETTLE_S
    sources: list = []
    while time.monotonic() < deadline:
        sources = sqs.list_dead_letter_source_queues(QueueUrl=kept_dlq).get("queueUrls", [])
        if src_for_kept in sources:
            break
        time.sleep(3)
    assert src_for_kept in sources, (
        f"kept dead-letter queue's sources read {sources!r} within {_SETTLE_S}s, expected to include "
        f"{src_for_kept!r}"
    )

    sqs.delete_queue(QueueUrl=doomed_dlq)

    # Deletion is eventually consistent; poll an independent read (GetQueueAttributes, not
    # ListDeadLetterSourceQueues) until it reports the queue gone, then hold
    # ListDeadLetterSourceQueues to the same refusal.
    read_err: dict = {}
    deadline = time.monotonic() + _SETTLE_S
    while time.monotonic() < deadline:
        try:
            sqs.get_queue_attributes(QueueUrl=doomed_dlq, AttributeNames=["QueueArn"])
        except ClientError as exc:
            read_err = exc.response.get("Error", {})
            break
        time.sleep(3)
    assert (read_err.get("Code"), read_err.get("Message")) == (_NOT_FOUND, _NOT_FOUND_MSG), (
        f"GetQueueAttributes on the deleted dead-letter queue answered {read_err!r} within "
        f"{_SETTLE_S}s"
    )

    list_err = _error(lambda: sqs.list_dead_letter_source_queues(QueueUrl=doomed_dlq))
    assert (list_err.get("Code"), list_err.get("Message")) == (_NOT_FOUND, _NOT_FOUND_MSG), (
        f"ListDeadLetterSourceQueues on the deleted dead-letter queue answered {list_err!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
