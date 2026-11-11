"""start-message-move-task-while-one-running-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-message-move-task-while-one-running-rejected"
GROUP = 'visibility_dlq'
SERVICES = ['sqs']

_TAGS = {"sim2real": "start-message-move-task-while-one-running-rejected"}
_N = 30
MSG_BUSY = ("There is already a task running. Only one active task is allowed for a source queue "
            "arn at a given time.")
_TERMINAL = {"COMPLETED", "CANCELLED", "FAILED"}


def _err(fn):
    """(Code, Message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        e = exc.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll(fn, pred, timeout_s, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val) and time.monotonic() < deadline:
        time.sleep(interval_s)
        val = fn()
    return val


def _tasks(sqs, arn):
    return sqs.list_message_move_tasks(SourceArn=arn, MaxResults=10).get("Results", [])


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A second StartMessageMoveTask on a DLQ with a task RUNNING is refused and adds no task; once
    the first is cancelled and settles, a new task starts, so one DLQ never has two movers."""
    sqs = ctx.client("sqs")
    base = ctx.unique_name("sim2real-behav-mmx-")
    src_url = sqs.create_queue(QueueName=base + "-src", tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=src_url))
    src_arn = sqs.get_queue_attributes(
        QueueUrl=src_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    dlq_url = sqs.create_queue(QueueName=base + "-dlq", tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = sqs.get_queue_attributes(
        QueueUrl=dlq_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=src_url, Attributes={"RedrivePolicy": json.dumps(
        {"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 1})})
    for i in range(0, _N, 10):
        sqs.send_message_batch(QueueUrl=dlq_url, Entries=[
            {"Id": str(j), "MessageBody": f"mmx-{i + j}"} for j in range(10)])

    def _depth():
        return int(sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=[
            "ApproximateNumberOfMessages"])["Attributes"]["ApproximateNumberOfMessages"])

    assert _poll(_depth, lambda d: d == _N, 60, 2.0) == _N, "the DLQ never showed all messages"

    # MaxNumberOfMessagesPerSecond=1 keeps the first task RUNNING for ~_N seconds.
    first = sqs.start_message_move_task(
        SourceArn=dlq_arn, DestinationArn=src_arn, MaxNumberOfMessagesPerSecond=1)
    handle = first["TaskHandle"]
    cancelled = []

    def _cancel():
        if not cancelled:
            try:
                sqs.cancel_message_move_task(TaskHandle=handle)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                    raise

    ctx.on_cleanup(_cancel)
    running = _poll(lambda: _tasks(sqs, dlq_arn),
                    lambda r: len(r) == 1 and r[0].get("Status") == "RUNNING", 30)
    assert len(running) == 1 and running[0].get("Status") == "RUNNING", (
        f"the first task was never observed RUNNING: {[t.get('Status') for t in running]!r}"
    )

    code, msg = _err(lambda: sqs.start_message_move_task(
        SourceArn=dlq_arn, DestinationArn=src_arn))
    assert code == "InvalidParameterValue", f"a second start on a busy source gave code {code!r}"
    assert msg == MSG_BUSY, f"a second start on a busy source gave message {msg!r}"

    listed = _tasks(sqs, dlq_arn)
    assert len(listed) == 1, (
        f"the refused second start added a task: ListMessageMoveTasks shows {len(listed)} "
        f"({[t.get('Status') for t in listed]!r})"
    )

    sqs.cancel_message_move_task(TaskHandle=handle)
    cancelled.append(True)
    settled = _poll(lambda: _tasks(sqs, dlq_arn),
                    lambda r: r and r[0].get("Status") in _TERMINAL, 120, 2.0)
    assert settled and settled[0].get("Status") == "CANCELLED", (
        f"the cancelled task did not settle on CANCELLED: "
        f"{[(t.get('Status'), t.get('FailureReason')) for t in settled]!r}"
    )

    second = sqs.start_message_move_task(SourceArn=dlq_arn, DestinationArn=src_arn)
    second_handle = second["TaskHandle"]
    assert second_handle != handle, "the new task reused the cancelled task's handle"
    done = _poll(lambda: _tasks(sqs, dlq_arn),
                 lambda r: r and r[0].get("Status") in _TERMINAL, 120, 2.0)
    assert done and done[0].get("Status") == "COMPLETED", (
        f"positive control: the task started after the cancel did not complete: "
        f"{[(t.get('Status'), t.get('FailureReason')) for t in done]!r}"
    )
    assert len(done) == 2, (
        f"after one cancelled and one completed task the source lists {len(done)} tasks, expected 2"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
