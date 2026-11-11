"""fifo-dead-letter-queue-move-sets-dedup-id-to-original-message-id."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fifo-dead-letter-queue-move-sets-dedup-id-to-original-message-id"
GROUP = "dlq"
SERVICES = ["sqs"]

_TAGS = {"sim2real:managed": "true", "sim2real": "fifo-dlq-dedup-id"}


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _queue_arn(sqs, url: str) -> str:
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]


def _budget_s(ctx, cap_s):
    """A wait's timeout, bounded by the runner's remaining time so the wait fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


def _receive_from_source(sqs, src_url, message_id, *, timeout_s):
    """Receive until the source delivers `message_id`; return it with its system attributes."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for msg in sqs.receive_message(
            QueueUrl=src_url,
            MaxNumberOfMessages=1,
            WaitTimeSeconds=2,
            MessageSystemAttributeNames=["All"],
        ).get("Messages", []):
            if msg["MessageId"] == message_id:
                return msg
    raise TimeoutError(f"the source never delivered {message_id!r} within {timeout_s:.0f}s")


def _await_dlq_arrival(sqs, src_url, dlq_url, *, token, timeout_s):
    """Drive the source's redelivery past maxReceiveCount and return the DLQ copy with its attributes."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for msg in sqs.receive_message(
            QueueUrl=src_url, MaxNumberOfMessages=1, WaitTimeSeconds=1
        ).get("Messages", []):
            sqs.change_message_visibility(
                QueueUrl=src_url, ReceiptHandle=msg["ReceiptHandle"], VisibilityTimeout=0
            )
        for msg in sqs.receive_message(
            QueueUrl=dlq_url,
            MaxNumberOfMessages=1,
            WaitTimeSeconds=1,
            MessageSystemAttributeNames=["All"],
        ).get("Messages", []):
            if token in msg["Body"]:
                return msg
    raise TimeoutError(f"{token!r} never reached the DLQ within {timeout_s:.0f}s")


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A message that maxReceiveCount moves from a FIFO queue to its FIFO dead-letter queue arrives
    there with its MessageDeduplicationId replaced by the original message's MessageId.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-configure-dead-letter-queue-redrive.html
    """
    sqs = ctx.client("sqs")
    suffix = ".fifo"

    dlq_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + "-dlq" + suffix,
        Attributes={"FifoQueue": "true"},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=dlq_url),
                              "AWS.SimpleQueueService.NonExistentQueue"))
    dlq_arn = _queue_arn(sqs, dlq_url)

    src_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + "-src" + suffix,
        Attributes={
            "FifoQueue": "true",
            "VisibilityTimeout": "1",
            "RedrivePolicy": json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 1}),
        },
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=src_url),
                              "AWS.SimpleQueueService.NonExistentQueue"))

    token = uuid.uuid4().hex[:8]
    body = f"fifo-dlq-dedup-{token}"
    dedup_id = f"dedup-{token}"
    sent_id = sqs.send_message(
        QueueUrl=src_url, MessageBody=body, MessageGroupId=ctx.unique_name("g-"),
        MessageDeduplicationId=dedup_id,
    )["MessageId"]

    # On the source the message carries the deduplication id it was sent with.
    first = _receive_from_source(sqs, src_url, sent_id, timeout_s=_budget_s(ctx, 30))
    assert first["Attributes"].get("MessageDeduplicationId") == dedup_id, (
        f"the source delivered MessageDeduplicationId "
        f"{first['Attributes'].get('MessageDeduplicationId')!r}, expected the sent {dedup_id!r}"
    )
    # Not deleted: the 1 s VisibilityTimeout lapses, so the next receive exceeds maxReceiveCount=1.

    dlq_msg = _await_dlq_arrival(sqs, src_url, dlq_url, token=token, timeout_s=_budget_s(ctx, 40))
    assert dlq_msg["Body"] == body, f"DLQ copy carried {dlq_msg['Body']!r}, expected {body!r}"
    dlq_dedup_id = dlq_msg["Attributes"].get("MessageDeduplicationId")
    assert dlq_dedup_id == sent_id, (
        f"a message moved from a FIFO queue to its FIFO DLQ must carry the original MessageId "
        f"{sent_id!r} as its MessageDeduplicationId, got {dlq_dedup_id!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
