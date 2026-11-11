"""e2e-dlq-redrive-full-cycle."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "e2e-dlq-redrive-full-cycle"
GROUP = "e2e_workflows"
SERVICES = ["sqs"]


@tags(
    "axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data"
)
def run(ctx: Any) -> None:
    """Messages that exhaust maxReceiveCount land in the DLQ, StartMessageMoveTask redrives them back
    to the source queue, and they are consumable there again.
    """
    sqs = ctx.client("sqs")

    dlq_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-e2edlq-dlq-"))[
        "QueueUrl"
    ]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    src_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-e2edlq-src-"),
        Attributes={
            "VisibilityTimeout": "1",
            "RedrivePolicy": json.dumps(
                {"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 1}
            ),
        },
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=src_url))
    src_arn = sqs.get_queue_attributes(QueueUrl=src_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    body = f"redrive-cycle-{src_url}"
    sqs.send_message(QueueUrl=src_url, MessageBody=body)

    first = sqs.receive_message(
        QueueUrl=src_url, MaxNumberOfMessages=1, WaitTimeSeconds=5
    )
    assert first.get("Messages"), "expected the first receive to return the message"
    # deliberately do not delete it, so the 1s visibility timeout lapses and the
    # next receive attempt exceeds maxReceiveCount=1, moving it to the DLQ

    dlq_message = None
    deadline = time.monotonic() + 40.0
    while time.monotonic() < deadline and dlq_message is None:
        sqs.receive_message(QueueUrl=src_url, MaxNumberOfMessages=1, WaitTimeSeconds=2)
        resp = sqs.receive_message(
            QueueUrl=dlq_url, MaxNumberOfMessages=1, WaitTimeSeconds=2
        )
        msgs = resp.get("Messages", [])
        if msgs:
            dlq_message = msgs[0]
    assert dlq_message is not None, "message was never moved to the DLQ"
    assert dlq_message["Body"] == body
    # keep the DLQ as StartMessageMoveTask needs to find it: present AND visible. The receive
    # above that confirmed arrival left it in-flight (the default 30s VisibilityTimeout), so
    # hand visibility back immediately rather than starting the move against an invisible
    # message.
    sqs.change_message_visibility(
        QueueUrl=dlq_url,
        ReceiptHandle=dlq_message["ReceiptHandle"],
        VisibilityTimeout=0,
    )

    # The source queue must have given the message up before the move starts.
    src_depth = None
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        src_depth = sqs.get_queue_attributes(
            QueueUrl=src_url, AttributeNames=["ApproximateNumberOfMessages"]
        )["Attributes"].get("ApproximateNumberOfMessages", "?")
        if src_depth == "0":
            break
        time.sleep(2.0)
    assert src_depth == "0", (
        f"source queue still reports {src_depth} message(s) before the move task starts"
    )

    move = sqs.start_message_move_task(SourceArn=dlq_arn, DestinationArn=src_arn)
    assert move.get("TaskHandle")

    # A COMPLETED entry drops TaskHandle (present only while RUNNING), so also match on SourceArn;
    # matching on TaskHandle alone never sees the terminal entry.
    status = None
    last_result = None
    deadline = time.monotonic() + 600.0
    while time.monotonic() < deadline:
        results = sqs.list_message_move_tasks(SourceArn=dlq_arn).get("Results", [])
        matching = [
            r
            for r in results
            if r.get("TaskHandle") == move["TaskHandle"] or r.get("SourceArn") == dlq_arn
        ]
        if matching:
            last_result = matching[0]
            status = last_result.get("Status")
            if status in ("COMPLETED", "FAILED", "CANCELLED"):
                break
        time.sleep(5.0)
    assert status == "COMPLETED", (
        f"expected move task to complete, got status={status!r}; last_result={last_result!r}"
    )

    # effect on the DLQ itself: a COMPLETED move must have drained it, not just reported success
    dlq_depth = sqs.get_queue_attributes(
        QueueUrl=dlq_url, AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]["ApproximateNumberOfMessages"]
    assert dlq_depth == "0", (
        f"DLQ still reports {dlq_depth} message(s) after a COMPLETED move task"
    )

    redelivered = None
    deadline = time.monotonic() + 40.0
    while time.monotonic() < deadline and redelivered is None:
        resp = sqs.receive_message(
            QueueUrl=src_url, MaxNumberOfMessages=1, WaitTimeSeconds=5
        )
        msgs = resp.get("Messages", [])
        if msgs:
            redelivered = msgs[0]
    assert redelivered is not None, (
        "redriven message never reappeared on the source queue"
    )
    assert redelivered["Body"] == body
    sqs.delete_message(QueueUrl=src_url, ReceiptHandle=redelivered["ReceiptHandle"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
