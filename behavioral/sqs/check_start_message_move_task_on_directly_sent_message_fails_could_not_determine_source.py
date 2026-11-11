"""start-message-move-task-on-directly-sent-message-fails-could-not-determine-source."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "start-message-move-task-on-directly-sent-message-fails-could-not-determine-source"
GROUP = "errors"
SERVICES = ["sqs"]

_TAGS = {"sim2real:managed": "true", "sim2real": "mmt-cndms"}
_TERMINAL = {"COMPLETED", "FAILED", "CANCELLED"}
_FAILURE_REASON = "CouldNotDetermineMessageSource"


def _queue_arn(sqs, url: str) -> str:
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]


def _poll(ctx, fn, pred, *, timeout_s, interval_s=2.0):
    """Poll fn() until pred holds; a timeout, capped by the runner's remaining time, raises."""
    budget = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + budget
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            raise TimeoutError(f"condition not met within {budget:.0f}s; last value {val!r}")
        time.sleep(interval_s)
        val = fn()
    return val


def _budget_s(ctx, cap_s):
    """A wait's timeout, bounded by the runner's remaining time so the wait fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


def _task(sqs, source_arn):
    results = sqs.list_message_move_tasks(SourceArn=source_arn, MaxResults=1).get("Results", [])
    return results[0] if results else {}


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartMessageMoveTask with no DestinationArn on a message sent straight to the DLQ starts,
    then settles FAILED with FailureReason CouldNotDetermineMessageSource, leaving the message on
    the DLQ; an explicit DestinationArn instead completes and delivers it there.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_StartMessageMoveTask.html
    """
    sqs = ctx.client("sqs")
    token = uuid.uuid4().hex[:8]

    dlq_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-") + "-dlq", tags=_TAGS)[
        "QueueUrl"
    ]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = _queue_arn(sqs, dlq_url)

    # Wires dlq_url as a real DLQ (StartMessageMoveTask refuses a SourceArn that is not one),
    # without ever redriving a message through it.
    owner_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + "-owner",
        Attributes={
            "RedrivePolicy": json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 5})
        },
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=owner_url))

    third_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-") + "-third", tags=_TAGS)[
        "QueueUrl"
    ]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=third_url))
    third_arn = _queue_arn(sqs, third_url)

    body = f"direct-to-dlq-{token}"
    sqs.send_message(QueueUrl=dlq_url, MessageBody=body)
    present = _poll(
        ctx,
        lambda: sqs.get_queue_attributes(
            QueueUrl=dlq_url, AttributeNames=["ApproximateNumberOfMessages"]
        )["Attributes"]["ApproximateNumberOfMessages"],
        lambda v: v == "1",
        timeout_s=30,
    )
    assert present == "1", (
        f"precondition: the directly-sent message must be visible on the DLQ before the move "
        f"task starts, got ApproximateNumberOfMessages={present!r}"
    )

    # Break: no DestinationArn, so AWS must infer the source from the message's redrive history,
    # and this message has none -- it was sent to the DLQ directly.
    handle = sqs.start_message_move_task(SourceArn=dlq_arn).get("TaskHandle")
    assert handle, "StartMessageMoveTask returned no TaskHandle"

    failed = _poll(ctx, lambda: _task(sqs, dlq_arn), lambda t: t.get("Status") in _TERMINAL,
                    timeout_s=90, interval_s=2.0)
    assert failed.get("Status") == "FAILED", (
        f"a move task with no DestinationArn over a directly-sent message must settle FAILED, "
        f"got Status={failed.get('Status')!r}"
    )
    assert failed.get("FailureReason") == _FAILURE_REASON, (
        f"expected FailureReason {_FAILURE_REASON!r}, got {failed.get('FailureReason')!r}"
    )

    # Effect absent: the message was never moved anywhere. ApproximateNumberOfMessages is
    # eventually consistent, so confirm presence by actually receiving it instead.
    still_there = _poll(
        ctx,
        lambda: sqs.receive_message(
            QueueUrl=dlq_url, MaxNumberOfMessages=1, WaitTimeSeconds=2, VisibilityTimeout=5
        ).get("Messages", []),
        lambda msgs: bool(msgs),
        timeout_s=30,
        interval_s=2.0,
    )
    assert still_there and still_there[0]["Body"] == body, (
        f"a FAILED move task must leave {body!r} receivable on the DLQ, got {still_there!r}"
    )
    sqs.change_message_visibility(
        QueueUrl=dlq_url, ReceiptHandle=still_there[0]["ReceiptHandle"], VisibilityTimeout=0
    )

    # Positive control: the identical source, with an explicit DestinationArn, needs no inferred
    # source and completes, delivering the message to that destination.
    handle2 = sqs.start_message_move_task(SourceArn=dlq_arn, DestinationArn=third_arn).get(
        "TaskHandle"
    )
    assert handle2, "StartMessageMoveTask with an explicit DestinationArn returned no TaskHandle"

    # The listing can still show the FAILED task first, so wait for the newer task to settle.
    completed = _poll(
        ctx,
        lambda: _task(sqs, dlq_arn),
        lambda t: (t.get("StartedTimestamp", 0) > failed["StartedTimestamp"]
                   and t.get("Status") in _TERMINAL),
        timeout_s=90,
        interval_s=2.0,
    )
    assert completed.get("Status") == "COMPLETED", (
        f"positive control: an explicit DestinationArn must complete, got "
        f"Status={completed.get('Status')!r} (FailureReason={completed.get('FailureReason')!r})"
    )

    delivered = _poll(
        ctx,
        lambda: sqs.receive_message(
            QueueUrl=third_url, MaxNumberOfMessages=1, WaitTimeSeconds=2
        ).get("Messages", []),
        lambda msgs: bool(msgs),
        timeout_s=30,
        interval_s=0.5,
    )
    assert len(delivered) == 1 and delivered[0]["Body"] == body, (
        f"positive control: expected {body!r} delivered to the explicit destination, got "
        f"{delivered!r}"
    )
    sqs.delete_message(QueueUrl=third_url, ReceiptHandle=delivered[0]["ReceiptHandle"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
