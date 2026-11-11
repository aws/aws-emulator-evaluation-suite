"""start-message-move-task-destination-arn-to-third-queue-bypasses-original-source."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "start-message-move-task-destination-arn-to-third-queue-bypasses-original-source"
GROUP = "dlq"
SERVICES = ["sqs"]

_TAGS = {"sim2real:managed": "true", "sim2real": "mmt-third-queue-destination"}
_TERMINAL = {"COMPLETED", "FAILED", "CANCELLED"}


def _queue_arn(sqs, url: str) -> str:
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]


def _poll(fn, pred, *, timeout_s, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartMessageMoveTask with an explicit DestinationArn moves a DLQ's messages to that third
    queue instead of the original source, which is never touched."""
    sqs = ctx.client("sqs")
    token = uuid.uuid4().hex[:8]

    dlq_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-dlq-"), tags=_TAGS)[
        "QueueUrl"
    ]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = _queue_arn(sqs, dlq_url)

    src_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-src-"),
        Attributes={
            "RedrivePolicy": json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 1})
        },
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=src_url))

    third_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-third-"), tags=_TAGS)[
        "QueueUrl"
    ]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=third_url))
    third_arn = _queue_arn(sqs, third_url)

    body = f"{token}-moved"
    sqs.send_message(QueueUrl=src_url, MessageBody=body)

    def _landed_in_dlq():
        for _ in range(8):
            r = sqs.receive_message(
                QueueUrl=src_url, MaxNumberOfMessages=1, WaitTimeSeconds=1, VisibilityTimeout=1
            )
            if not r.get("Messages"):
                break
            time.sleep(2)
        return sqs.get_queue_attributes(
            QueueUrl=dlq_url, AttributeNames=["ApproximateNumberOfMessages"]
        )["Attributes"]["ApproximateNumberOfMessages"]

    landed = _poll(_landed_in_dlq, lambda v: v == "1", timeout_s=30, interval_s=3)
    assert landed == "1", (
        f"precondition: {body!r} must have redriven into the DLQ before the move task is "
        f"started; the DLQ's ApproximateNumberOfMessages read {landed!r}"
    )

    handle = sqs.start_message_move_task(SourceArn=dlq_arn, DestinationArn=third_arn)[
        "TaskHandle"
    ]
    assert handle, "StartMessageMoveTask returned no TaskHandle"

    def _task():
        results = sqs.list_message_move_tasks(SourceArn=dlq_arn, MaxResults=1).get("Results", [])
        return results[0] if results else {}

    task = _poll(_task, lambda t: t.get("Status") in _TERMINAL, timeout_s=60, interval_s=2)
    assert task.get("Status") == "COMPLETED", f"move task did not complete: {task!r}"
    assert task.get("DestinationArn") == third_arn, (
        f"task recorded DestinationArn {task.get('DestinationArn')!r}, expected {third_arn!r}"
    )

    src_count = _poll(
        lambda: sqs.get_queue_attributes(
            QueueUrl=src_url, AttributeNames=["ApproximateNumberOfMessages"]
        )["Attributes"]["ApproximateNumberOfMessages"],
        lambda v: v == "0",
        timeout_s=15,
        interval_s=2,
    )
    assert src_count == "0", (
        f"original source must never receive the move despite being the DLQ's configured "
        f"source, got ApproximateNumberOfMessages={src_count!r}"
    )

    landed = sqs.receive_message(QueueUrl=third_url, MaxNumberOfMessages=1, WaitTimeSeconds=5).get(
        "Messages", []
    )
    assert len(landed) == 1 and landed[0]["Body"] == body, (
        f"expected the moved message {body!r} at the explicit third-queue destination, "
        f"got {landed!r}"
    )
    sqs.delete_message(QueueUrl=third_url, ReceiptHandle=landed[0]["ReceiptHandle"])

    dlq_count = _poll(
        lambda: sqs.get_queue_attributes(
            QueueUrl=dlq_url, AttributeNames=["ApproximateNumberOfMessages"]
        )["Attributes"]["ApproximateNumberOfMessages"],
        lambda v: v == "0",
        timeout_s=30,
        interval_s=2,
    )
    assert dlq_count == "0", f"DLQ must be drained by the completed move, got {dlq_count!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
