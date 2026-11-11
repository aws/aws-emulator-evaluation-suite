"""message-move-task-redrives-dlq-back-to-source."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "message-move-task-redrives-dlq-back-to-source"
GROUP = "state"
SERVICES = ["sqs"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartMessageMoveTask on a DLQ moves its messages back to their original source
    queue and the task's Status transitions RUNNING -> COMPLETED."""
    sqs = ctx.client("sqs")
    dlq_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-sqs-mmt-dlq-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]

    redrive_policy = json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 1})
    src_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-sqs-mmt-src-"),
        Attributes={"VisibilityTimeout": "2", "RedrivePolicy": redrive_policy},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=src_url))

    body = "move-task-roundtrip"
    sqs.send_message(QueueUrl=src_url, MessageBody=body)

    # drive it into the DLQ via a real redrive (receive once, let it expire, receive again)
    first = _poll_receive_one(sqs, src_url, timeout_s=20.0)
    assert first["Body"] == body, f"expected {body!r} on first receive, got {first['Body']!r}"

    # wait past the 2s visibility timeout via a bounded retry (never a bare sleep), then
    # actively attempt redelivery from the source queue so SQS evaluates maxReceiveCount
    # (1) and routes the message to the DLQ. Each call's WaitTimeSeconds=2 long-polls, so
    # the retry loop itself carries the wait.
    redeliver_deadline = time.monotonic() + 20.0
    while time.monotonic() < redeliver_deadline:
        sqs.receive_message(QueueUrl=src_url, MaxNumberOfMessages=1, WaitTimeSeconds=2)

    dlq_msg = _poll_receive_one(sqs, dlq_url, timeout_s=90.0)
    assert dlq_msg["Body"] == body, f"expected {body!r} in the DLQ after redrive, got {dlq_msg['Body']!r}"
    # leave it un-deleted in the DLQ so the move task has something to move

    sqs.start_message_move_task(SourceArn=dlq_arn)["TaskHandle"]

    # Only one active message-move task is supported per queue at a time, and
    # ListMessageMoveTasks returns the most recent task first; TaskHandle may be
    # dropped from the entry once the task is no longer active, so match on
    # SourceArn/recency instead of trying to match the handle by identity.
    def _task_status():
        results = sqs.list_message_move_tasks(SourceArn=dlq_arn, MaxResults=1)["Results"]
        if not results:
            return None
        return results[0].get("Status")

    _poll_until(_task_status, lambda s: s == "COMPLETED", timeout_s=90.0, interval_s=3.0)

    # the message must now be back on the source queue
    moved_back = _poll_receive_one(sqs, src_url, timeout_s=30.0)
    assert moved_back["Body"] == body, (
        f"expected {body!r} back on the source queue after COMPLETED, got {moved_back['Body']!r}"
    )
    sqs.delete_message(QueueUrl=src_url, ReceiptHandle=moved_back["ReceiptHandle"])

    # the DLQ must have given the message up, not merely copied it
    def _dlq_depth():
        return sqs.get_queue_attributes(
            QueueUrl=dlq_url, AttributeNames=["ApproximateNumberOfMessages"]
        )["Attributes"].get("ApproximateNumberOfMessages")

    dlq_depth = _poll_until(_dlq_depth, lambda v: v == "0", timeout_s=30.0, interval_s=2.0)
    assert dlq_depth == "0", f"expected DLQ depth 0 after the move, got {dlq_depth!r}"


def _poll_receive_one(sqs, url, timeout_s=20.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=3)
        messages = resp.get("Messages", [])
        if messages:
            return messages[0]
    raise AssertionError(f"no message received from {url} within {timeout_s}s")


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
