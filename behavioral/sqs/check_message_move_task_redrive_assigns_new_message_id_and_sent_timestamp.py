"""message-move-task-redrive-assigns-new-message-id-and-sent-timestamp."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "message-move-task-redrive-assigns-new-message-id-and-sent-timestamp"
GROUP = "dlq"
SERVICES = ["sqs"]

_TAGS = {"sim2real:managed": "true", "sim2real": "mmt-new-id-and-timestamp"}
_TERMINAL = {"COMPLETED", "FAILED", "CANCELLED"}


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
    """A message that StartMessageMoveTask redrives from a DLQ back to its source arrives there
    with a MessageId and a SentTimestamp distinct from the copy that sat in the DLQ.
    """
    sqs = ctx.client("sqs")

    dlq_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-") + "-dlq", tags=_TAGS)[
        "QueueUrl"
    ]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=dlq_url),
                              "AWS.SimpleQueueService.NonExistentQueue"))
    dlq_arn = _queue_arn(sqs, dlq_url)

    src_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + "-src",
        Attributes={
            "VisibilityTimeout": "1",
            "RedrivePolicy": json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 1}),
        },
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=src_url),
                              "AWS.SimpleQueueService.NonExistentQueue"))
    src_arn = _queue_arn(sqs, src_url)

    token = uuid.uuid4().hex[:8]
    body = f"mmt-id-{token}"
    sqs.send_message(QueueUrl=src_url, MessageBody=body)

    first = _poll(
        ctx,
        lambda: sqs.receive_message(QueueUrl=src_url, MaxNumberOfMessages=1, WaitTimeSeconds=5),
        lambda r: r.get("Messages"),
        timeout_s=30,
    )
    assert first.get("Messages"), "expected the first receive on the source to return the message"
    # don't delete: let the 1s VisibilityTimeout lapse so the next receive exceeds maxReceiveCount=1

    dlq_msg = _await_dlq_arrival(sqs, src_url, dlq_url, token=token, timeout_s=_budget_s(ctx, 40))
    assert dlq_msg["Body"] == body, f"DLQ copy carried {dlq_msg['Body']!r}, expected {body!r}"
    dlq_message_id = dlq_msg["MessageId"]
    dlq_sent_ts = dlq_msg["Attributes"]["SentTimestamp"]
    # the receive above left it in-flight for the DLQ's default VisibilityTimeout; release it so
    # StartMessageMoveTask finds it present and visible.
    sqs.change_message_visibility(
        QueueUrl=dlq_url, ReceiptHandle=dlq_msg["ReceiptHandle"], VisibilityTimeout=0
    )

    handle = sqs.start_message_move_task(SourceArn=dlq_arn, DestinationArn=src_arn).get(
        "TaskHandle"
    )
    assert handle, "StartMessageMoveTask returned no TaskHandle"

    def _task():
        results = sqs.list_message_move_tasks(SourceArn=dlq_arn, MaxResults=1).get("Results", [])
        return results[0] if results else {}

    task = _poll(ctx, _task, lambda t: t.get("Status") in _TERMINAL, timeout_s=90, interval_s=2.0)
    assert task.get("Status") == "COMPLETED", (
        f"move task ended in Status={task.get('Status')!r} "
        f"(FailureReason={task.get('FailureReason')!r}), expected COMPLETED"
    )

    moved = _poll(
        ctx,
        lambda: sqs.receive_message(
            QueueUrl=src_url,
            MaxNumberOfMessages=1,
            WaitTimeSeconds=5,
            MessageSystemAttributeNames=["All"],
        ),
        lambda r: r.get("Messages"),
        timeout_s=60,
    )
    assert moved.get("Messages"), "redriven message never reappeared on the source queue"
    moved_msg = moved["Messages"][0]
    assert moved_msg["Body"] == body, (
        f"redelivered message carried {moved_msg['Body']!r}, expected {body!r}"
    )
    sqs.delete_message(QueueUrl=src_url, ReceiptHandle=moved_msg["ReceiptHandle"])

    assert moved_msg["MessageId"] != dlq_message_id, (
        f"the redriven message kept the DLQ copy's MessageId {dlq_message_id!r} instead of "
        f"being assigned a new one"
    )
    moved_sent_ts = moved_msg["Attributes"]["SentTimestamp"]
    assert moved_sent_ts != dlq_sent_ts, (
        f"the redriven message kept the DLQ copy's SentTimestamp {dlq_sent_ts!r} instead of "
        f"being assigned a new one ({moved_sent_ts!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
