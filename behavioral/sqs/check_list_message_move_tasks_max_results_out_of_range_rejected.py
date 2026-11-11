"""list-message-move-tasks-max-results-out-of-range-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-message-move-tasks-max-results-out-of-range-rejected"
GROUP = 'visibility_dlq'
SERVICES = ['sqs']

_TAGS = {"sim2real": "list-message-move-tasks-max-results-out-of-range-rejected"}
MSG_RANGE = ("Value for parameter MaxResults is invalid. Reason: You must enter a number that's "
             "between 1 and 10.")
_TERMINAL = {"COMPLETED", "CANCELLED", "FAILED"}


def _err(fn):
    """(Code, Message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        e = exc.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListMessageMoveTasks refuses MaxResults 0 and 11 with InvalidParameterValue and the 1..10
    range message on a DLQ with a completed task; MaxResults=10 lists that task as COMPLETED and
    both messages end up on the destination."""
    sqs = ctx.client("sqs")
    base = ctx.unique_name("sim2real-behav-lmr-")
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
    sqs.send_message(QueueUrl=dlq_url, MessageBody="lmr-0")
    sqs.send_message(QueueUrl=dlq_url, MessageBody="lmr-1")

    deadline = time.monotonic() + 60
    while True:
        depth = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=[
            "ApproximateNumberOfMessages"])["Attributes"]["ApproximateNumberOfMessages"]
        if depth == "2" or time.monotonic() > deadline:
            break
        time.sleep(2)
    assert depth == "2", f"the DLQ shows {depth!r} messages, expected '2'"

    sqs.start_message_move_task(SourceArn=dlq_arn, DestinationArn=src_arn)
    deadline = time.monotonic() + 120
    while True:
        res = sqs.list_message_move_tasks(SourceArn=dlq_arn).get("Results", [])
        if (res and res[0].get("Status") in _TERMINAL) or time.monotonic() > deadline:
            break
        time.sleep(2)
    assert res and res[0].get("Status") == "COMPLETED", (
        f"the move task did not complete: {[(t.get('Status'), t.get('FailureReason')) for t in res]!r}"
    )

    # The upper bound is 10, not the 1000 of ListQueues.
    for bad in (0, 11):
        code, msg = _err(lambda b=bad: sqs.list_message_move_tasks(SourceArn=dlq_arn, MaxResults=b))
        assert code == "InvalidParameterValue", f"MaxResults={bad} gave code {code!r}"
        assert msg == MSG_RANGE, f"MaxResults={bad} gave message {msg!r}"

    listed = sqs.list_message_move_tasks(SourceArn=dlq_arn, MaxResults=10).get("Results", [])
    assert len(listed) == 1, f"MaxResults=10 listed {len(listed)} tasks, expected the one task"
    task = listed[0]
    assert task.get("Status") == "COMPLETED", (
        f"the listed task reads Status={task.get('Status')!r}, expected COMPLETED"
    )
    assert (task.get("SourceArn"), task.get("DestinationArn")) == (dlq_arn, src_arn), (
        "the listed task does not name the DLQ as source and the source queue as destination"
    )
    # ApproximateNumberOfMessagesMoved on a COMPLETED record can still read 0, so the
    # move is graded by where the messages are, not by the approximate counter.

    def _depths():
        return tuple(sqs.get_queue_attributes(QueueUrl=u, AttributeNames=[
            "ApproximateNumberOfMessages"])["Attributes"]["ApproximateNumberOfMessages"]
            for u in (dlq_url, src_url))

    deadline = time.monotonic() + 60
    depths = _depths()
    while depths != ("0", "2") and time.monotonic() < deadline:
        time.sleep(2)
        depths = _depths()
    assert depths == ("0", "2"), (
        f"after the completed move the DLQ and destination hold {depths!r}, expected ('0', '2')"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
