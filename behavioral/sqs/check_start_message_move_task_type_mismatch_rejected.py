"""start-message-move-task-type-mismatch-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-message-move-task-type-mismatch-rejected"
GROUP = "errors"
SERVICES = ["sqs"]

_TAGS = {"sim2real:managed": "true", "sim2real": "mmt-type-mismatch-rejected"}

# A FIFO DLQ redirected at a standard destination is
# refused with this exact message, before any task is created.
_MISMATCH_MESSAGE = "The source queue and destination queue must be of the same queue type."


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator accepting input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll(fn, pred, *, timeout_s, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartMessageMoveTask from a FIFO DLQ to a standard queue is rejected with
    InvalidParameterValue and its exact message before any task is created, while the FIFO
    DLQ's original FIFO source as destination is accepted."""
    sqs = ctx.client("sqs")
    token = uuid.uuid4().hex[:8]

    dlq_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-dlq-") + ".fifo",
        Attributes={"FifoQueue": "true"},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    src_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-src-") + ".fifo",
        Attributes={
            "FifoQueue": "true",
            "RedrivePolicy": json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 1}),
        },
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=src_url))
    src_arn = sqs.get_queue_attributes(QueueUrl=src_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    mismatched_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-std-"), tags=_TAGS)[
        "QueueUrl"
    ]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=mismatched_url))
    mismatched_arn = sqs.get_queue_attributes(QueueUrl=mismatched_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    body = f"{token}-mismatch"
    sqs.send_message(QueueUrl=src_url, MessageBody=body, MessageGroupId="g1", MessageDeduplicationId=token)

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

    code, message = _error(
        lambda: sqs.start_message_move_task(SourceArn=dlq_arn, DestinationArn=mismatched_arn)
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    assert message == _MISMATCH_MESSAGE, f"unexpected refusal message {message!r}"

    tasks_after_reject = sqs.list_message_move_tasks(SourceArn=dlq_arn).get("Results", [])
    assert tasks_after_reject == [], (
        f"the rejected call left move task(s) behind: {tasks_after_reject!r}"
    )

    # Positive control: a same-type destination (the original FIFO source) is accepted.
    handle = sqs.start_message_move_task(SourceArn=dlq_arn, DestinationArn=src_arn)["TaskHandle"]
    assert handle, "same-type destination unexpectedly produced no TaskHandle"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
