"""op-cancel-unknown-move-task-rejected."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-cancel-unknown-move-task-rejected"
GROUP = 'errors'
SERVICES = ['sqs']

_UNKNOWN_TASK_MESSAGE = "Task does not exist."

_TAGS = {"sim2real:managed": "true", "sim2real": "op-cancel-unknown-move-task-rejected"}
# MaxNumberOfMessagesPerSecond=1 over _N=40 messages gives a ~40s RUNNING window, so the
# positive-control cancel below lands on a task that is still moving messages.
_N = 40
_RATE = 1
_TERMINAL = {"CANCELLED", "COMPLETED", "FAILED"}


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected CancelMessageMoveTask to be rejected, got a response: {result!r}")


def _poll(fn, pred, *, timeout_s, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _task(sqs, source_arn):
    results = sqs.list_message_move_tasks(SourceArn=source_arn, MaxResults=10).get("Results", [])
    return results[0] if len(results) == 1 else {}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelMessageMoveTask rejects a well-formed handle naming an unknown task id with
    ResourceNotFoundException, after cancelling a real RUNNING task succeeds (so it does not refuse
    every cancel); the real task's CANCELLED record is left unchanged."""
    sqs = ctx.client("sqs")

    dlq_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-") + "-dlq", tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    dest_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-") + "-dest", tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dest_url))
    dest_arn = sqs.get_queue_attributes(QueueUrl=dest_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    # StartMessageMoveTask refuses a source that is not a dead-letter queue for any queue, so this
    # RedrivePolicy is what makes dlq_url eligible as a move-task source.
    sqs.set_queue_attributes(
        QueueUrl=dest_url,
        Attributes={"RedrivePolicy": json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 1})},
    )

    for i in range(_N):
        sqs.send_message(QueueUrl=dlq_url, MessageBody=f"cancel-unknown-positive-control-{i}")

    real_handle = sqs.start_message_move_task(
        SourceArn=dlq_arn, DestinationArn=dest_arn, MaxNumberOfMessagesPerSecond=_RATE,
    )["TaskHandle"]

    running = _poll(lambda: _task(sqs, dlq_arn), lambda r: r.get("Status") == "RUNNING",
                    timeout_s=60, interval_s=1.0)
    assert running.get("Status") == "RUNNING", (
        f"positive control: the move task was never observed RUNNING, so cancelling it below "
        f"would prove nothing: ListMessageMoveTasks reported {running!r}"
    )

    # Positive control: CancelMessageMoveTask against THIS real, running task must succeed.
    sqs.cancel_message_move_task(TaskHandle=real_handle)

    settled = _poll(lambda: _task(sqs, dlq_arn), lambda r: r.get("Status") in _TERMINAL,
                    timeout_s=120, interval_s=2.0)
    assert settled.get("Status") == "CANCELLED", (
        f"positive control: cancelling a real running task must settle on CANCELLED, got "
        f"{settled.get('Status')!r} (ListMessageMoveTasks reported {settled!r})"
    )

    # Now break exactly one thing: a task handle shaped like a real one (same encoding, a real
    # queue ARN) but naming a task id that was never issued.
    bogus = base64.b64encode(
        json.dumps({"taskId": "00000000-0000-0000-0000-000000000000", "sourceArn": dlq_arn}).encode()
    ).decode()

    error = _client_error(lambda: sqs.cancel_message_move_task(TaskHandle=bogus))
    assert error.get("Code") == "ResourceNotFoundException", (
        f"CancelMessageMoveTask on a handle naming an unknown task id must fail with "
        f"ResourceNotFoundException, got {error.get('Code')!r}"
    )
    assert error.get("Message") == _UNKNOWN_TASK_MESSAGE, (
        f"expected message {_UNKNOWN_TASK_MESSAGE!r}, got {error.get('Message')!r}"
    )

    # Effect-absent, via an independent read: the rejected cancel on a bogus handle must not
    # have disturbed the real task's own terminal record.
    after = _task(sqs, dlq_arn)
    assert after.get("Status") == "CANCELLED", (
        f"the rejected cancel on a bogus handle changed the real task's recorded status: "
        f"before=CANCELLED after={after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
