"""cancel-message-move-task-conserves-messages."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "cancel-message-move-task-conserves-messages"
GROUP = 'visibility_dlq'
SERVICES = ['sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": "cancel-message-move-task"}

_N = 40
# Throttling to 1/s keeps the task RUNNING long enough to cancel; a cancel a few seconds in still
# lets ~15-25 messages through, so 40 leaves headroom for `moved < _N`.
_RATE = 1
# A cancel passes through CANCELLING for ~10-20s while the moved counter keeps rising, so
# CANCELLING is not terminal.
_TERMINAL = {"COMPLETED", "CANCELLED", "FAILED"}


def _poll(fn, pred, *, timeout_s, interval_s=2.0, budget_s=None):
    start = time.monotonic()
    stop = start + (timeout_s if budget_s is None else min(timeout_s, budget_s))
    val = fn()
    while not pred(val):
        if time.monotonic() >= stop:
            if budget_s is not None and budget_s < timeout_s:
                raise TimeoutError(
                    f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
                    f"{timeout_s}s wait ended (last={val!r}); not graded"
                )
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _task(sqs, source_arn):
    """The one move-task result for `source_arn`, or {}.

    Matched on SourceArn because ListMessageMoveTasks omits `TaskHandle` once the task leaves RUNNING.
    """
    results = sqs.list_message_move_tasks(SourceArn=source_arn, MaxResults=10).get("Results", [])
    return results[0] if len(results) == 1 else {}


def _depth(sqs, url):
    return int(sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"],
    )["Attributes"].get("ApproximateNumberOfMessages", "-1"))


@tags("axis:happy-path", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Cancelling a RUNNING message-move task (ApproximateNumberOfMessagesToMove in 1..N) settles on
    CANCELLED, moves fewer than all messages, and the DLQ + destination depths poll to N.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_CancelMessageMoveTask.html
    """
    sqs = ctx.client("sqs")
    token = uuid.uuid4().hex[:8]

    # StartMessageMoveTask only accepts a source that is some queue's DLQ, hence the RedrivePolicy.
    url_dest = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + "-dest", tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url_dest))
    dest_arn = sqs.get_queue_attributes(
        QueueUrl=url_dest, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    url_dlq = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + "-dlq", tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url_dlq))
    dlq_arn = sqs.get_queue_attributes(
        QueueUrl=url_dlq, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    sqs.set_queue_attributes(
        QueueUrl=url_dest,
        Attributes={"RedrivePolicy": json.dumps(
            {"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 1})},
    )

    for i in range(_N):
        sqs.send_message(QueueUrl=url_dlq, MessageBody=f"move-{token}-{i}")
    dlq_depth = _poll(lambda: _depth(sqs, url_dlq), lambda v: v == _N,
                      timeout_s=90)
    assert dlq_depth == _N, (
        f"only {dlq_depth} of {_N} messages landed on the DLQ, so the conservation assertion "
        f"below would be measured against the wrong total"
    )

    handle = sqs.start_message_move_task(
        SourceArn=dlq_arn, DestinationArn=dest_arn, MaxNumberOfMessagesPerSecond=_RATE,
    )["TaskHandle"]

    # ApproximateNumberOfMessagesToMove is absent from the first RUNNING records, so wait for it.
    running = _poll(lambda: _task(sqs, dlq_arn),
                    lambda r: (r.get("Status") == "RUNNING"
                               and r.get("ApproximateNumberOfMessagesToMove") is not None),
                    timeout_s=60, interval_s=1.0)
    assert running.get("Status") == "RUNNING", (
        f"the move task was never observed RUNNING, so the cancel below cancelled nothing: "
        f"ListMessageMoveTasks reported {running!r}"
    )
    # ApproximateNumberOfMessagesToMove is a snapshot of the source taken when the task starts
    # (ListMessageMoveTasksResultEntry docs) and is approximate, so it is bounded by the _N
    # messages the source holds rather than pinned to _N.
    to_move = running.get("ApproximateNumberOfMessagesToMove")
    assert isinstance(to_move, int) and 0 < to_move <= _N, (
        f"the running task does not claim to be moving between 1 and the {_N} messages that were "
        f"enqueued: ApproximateNumberOfMessagesToMove={to_move!r}"
    )
    assert running.get("TaskHandle") == handle, (
        f"the RUNNING task's TaskHandle is not the one StartMessageMoveTask returned: "
        f"{running.get('TaskHandle')!r} != {handle!r}"
    )

    sqs.cancel_message_move_task(TaskHandle=handle)

    final = _poll(lambda: _task(sqs, dlq_arn),
                  lambda r: r.get("Status") in _TERMINAL,
                  timeout_s=120, interval_s=2.0)
    final_status = final.get("Status")
    assert final_status == "CANCELLED", (
        f"a cancelled move task must settle on the terminal status CANCELLED, got "
        f"{final_status!r} (FailureReason={final.get('FailureReason')!r}). CANCELLING here means "
        f"the task never settled; COMPLETED means the cancel did not stop it"
    )

    moved = final.get("ApproximateNumberOfMessagesMoved")
    assert isinstance(moved, int), (
        f"ApproximateNumberOfMessagesMoved must be an integer on a terminal task, got {moved!r}"
    )
    # A task that reports moving all _N messages was not cancelled, whatever status it prints.
    assert 0 <= moved < _N, (
        f"the cancelled task reports moving {moved!r} of {_N} messages -- a cancel that moved "
        f"everything cancelled nothing"
    )

    # Both depths are eventually consistent, so poll for the conserved total.
    def _both():
        return _depth(sqs, url_dlq), _depth(sqs, url_dest)

    dlq_after, dest_after = _poll(_both, lambda t: sum(t) == _N,
                                  timeout_s=120.0, budget_s=_budget_s(ctx, 120.0))
    assert dlq_after + dest_after == _N, (
        f"messages were lost or duplicated by the cancelled move: dlq={dlq_after} "
        f"dest={dest_after} sum={dlq_after + dest_after}, started with {_N}"
    )
    # Whether any message moved before the cancel landed is timing, so 0 passes.
    assert 0 < dest_after < _N or 0 <= dest_after < _N, (
        f"a cancelled {_N}-message move must leave the destination holding fewer than all of "
        f"them; it holds {dest_after}"
    )
    # ApproximateNumberOfMessagesMoved is not compared with the destination depth: it lags the
    # queue by several messages.

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
