"""message-move-task-completes-and-drains-dlq."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "message-move-task-completes-and-drains-dlq"
GROUP = 'visibility_dlq'
SERVICES = ['sqs']

TERMINAL = ("COMPLETED", "FAILED", "CANCELLED")

_TAGS = {"sim2real:managed": "true", "sim2real": "message-move-task-completes-and-drains-dlq"}

def _poll(fn, pred, *, timeout_s, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _peek(sqs, url, *, expect, timeout_s):
    """Collect distinct bodies WITHOUT consuming them: VisibilityTimeout=0 keeps each message
    immediately visible again, so the queue is left as it was found."""
    seen = {}
    deadline = time.monotonic() + timeout_s
    while len(seen) < expect and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
        for msg in resp.get("Messages", []):
            seen[msg["MessageId"]] = msg["Body"]
            sqs.change_message_visibility(
                QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"], VisibilityTimeout=0
            )
    return sorted(seen.values())


def _drain(sqs, url, *, expect, timeout_s):
    """Receive-and-delete distinct messages, returning their bodies sorted."""
    seen = {}
    deadline = time.monotonic() + timeout_s
    while len(seen) < expect and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
        for msg in resp.get("Messages", []):
            seen[msg["MessageId"]] = msg["Body"]
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return sorted(seen.values())


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A message move task from a DLQ reaches Status=COMPLETED exactly, reports the messages moved
    and to move, redelivers them on the destination queue, and leaves the DLQ empty.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_StartMessageMoveTask.html
    """
    sqs = ctx.client("sqs")

    # Created first so LIFO teardown deletes the dead-letter target last.
    dlq_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + "-dlq", tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    src_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + "-src",
        Attributes={
            "VisibilityTimeout": "1",
            "RedrivePolicy": (
                '{"deadLetterTargetArn":"%s","maxReceiveCount":1}' % dlq_arn
            ),
        },
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=src_url))
    src_arn = sqs.get_queue_attributes(QueueUrl=src_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    token = uuid.uuid4().hex[:8]
    bodies = sorted(f"move-{i}-{token}" for i in range(2))
    for body in bodies:
        sqs.send_message(QueueUrl=src_url, MessageBody=body)

    # --- land both messages in the DLQ ------------------------------------------------
    # Redrive fires on the receive that would take a message PAST maxReceiveCount, so one delivery
    # each is not enough; re-receive (VisibilityTimeout=0 re-exposes each) until the DLQ fills.
    delivered: dict[str, int] = {}
    deadline = time.monotonic() + 150
    dlq_depth = "0"
    while time.monotonic() < deadline:
        for msg in sqs.receive_message(
            QueueUrl=src_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=1,
            AttributeNames=["ApproximateReceiveCount"],
        ).get("Messages", []):
            delivered[msg["Body"]] = delivered.get(msg["Body"], 0) + 1
            sqs.change_message_visibility(
                QueueUrl=src_url, ReceiptHandle=msg["ReceiptHandle"], VisibilityTimeout=0
            )
        dlq_depth = sqs.get_queue_attributes(
            QueueUrl=dlq_url, AttributeNames=["ApproximateNumberOfMessages"]
        )["Attributes"].get("ApproximateNumberOfMessages", "0")
        if int(dlq_depth) >= len(bodies):
            break
    assert set(delivered) == set(bodies), (
        f"could not deliver both messages on the source queue: got {sorted(delivered)}"
    )
    # The source must have given each message up rather than kept redelivering it.
    src_depth = _poll(
        lambda: sqs.get_queue_attributes(
            QueueUrl=src_url, AttributeNames=["ApproximateNumberOfMessages"]
        )["Attributes"].get("ApproximateNumberOfMessages", "?"),
        lambda v: v == "0",
        timeout_s=60,
    )
    assert src_depth == "0", (
        f"source queue still reports {src_depth} message(s) after redrive; the messages were "
        f"not moved off it (deliveries per message: {delivered})"
    )

    in_dlq = _peek(sqs, dlq_url, expect=2, timeout_s=90)
    assert in_dlq == bodies, (
        f"redrive did not land both messages in the DLQ: {in_dlq} != {bodies}"
    )

    # --- start the move task and poll it to a TERMINAL status --------------------------
    started = sqs.start_message_move_task(SourceArn=dlq_arn, DestinationArn=src_arn)
    handle = started.get("TaskHandle")
    assert handle, f"StartMessageMoveTask returned no TaskHandle: {sorted(started)}"

    def _task():
        for res in sqs.list_message_move_tasks(SourceArn=dlq_arn, MaxResults=10).get(
            "Results", []
        ):
            if res.get("TaskHandle") == handle or res.get("SourceArn") == dlq_arn:
                return res
        return {}

    task = _poll(
        _task,
        lambda t: t.get("Status") in TERMINAL,
        timeout_s=180,
    )
    assert task, f"ListMessageMoveTasks reported no task for source {dlq_arn}"
    assert task.get("Status") == "COMPLETED", (
        f"move task ended in Status={task.get('Status')!r} "
        f"(FailureReason={task.get('FailureReason')!r}), expected COMPLETED"
    )
    assert task.get("DestinationArn") == src_arn, (
        f"task DestinationArn {task.get('DestinationArn')!r} != {src_arn!r}"
    )
    # ApproximateNumberOfMessagesMoved lags the COMPLETED status by seconds, so poll for it. A
    # COMPLETED entry drops TaskHandle, which is why _task() also matches on SourceArn.
    task = _poll(
        _task,
        lambda t: (t.get("ApproximateNumberOfMessagesMoved") or 0) >= len(bodies),
        timeout_s=120,
        interval_s=3.0,
    )
    moved = task.get("ApproximateNumberOfMessagesMoved")
    assert isinstance(moved, int) and moved >= len(bodies), (
        f"ApproximateNumberOfMessagesMoved={moved!r} for a {len(bodies)}-message task -- a "
        "COMPLETED task that moved nothing is the stub this check exists to catch"
    )
    # A COMPLETED task also publishes what it set out to move; anything else means the task
    # never sized the DLQ it drained.
    to_move = task.get("ApproximateNumberOfMessagesToMove")
    assert to_move == len(bodies), (
        f"a COMPLETED task over a {len(bodies)}-message DLQ must report "
        f"ApproximateNumberOfMessagesToMove={len(bodies)}, got {to_move!r} ({task!r})"
    )

    # --- the messages really are back on the destination ------------------------------
    back = _drain(sqs, src_url, expect=2, timeout_s=90)
    assert back == bodies, f"destination queue received {back}, expected {bodies}"

    # --- effect on the source of the move: the DLQ is drained -------------------------
    dlq_depth = _poll(
        lambda: sqs.get_queue_attributes(
            QueueUrl=dlq_url,
            AttributeNames=["ApproximateNumberOfMessages"],
        )["Attributes"].get("ApproximateNumberOfMessages", "?"),
        lambda v: v == "0",
        timeout_s=60,
    )
    assert dlq_depth == "0", (
        f"DLQ still reports {dlq_depth} message(s) after a COMPLETED move task"
    )
    left = _peek(sqs, dlq_url, expect=1, timeout_s=10)
    assert left == [], f"DLQ still delivers {left} after a COMPLETED move task"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
