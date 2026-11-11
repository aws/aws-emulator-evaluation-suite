"""dlq-redrive."""
from __future__ import annotations

import json
import uuid

from behavioral_harness import tags

CHECK = "dlq-redrive"
GROUP = 'visibility_dlq'
SERVICES = ['sqs']

@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """After maxReceiveCount is exceeded the message moves to the DLQ, and not on its first
    delivery.
    """
    sqs = ctx.client("sqs")
    dlq_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    main_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"),
        Attributes={
            "RedrivePolicy": json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 2})
        },
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=main_url))
    body = f"dlq-{uuid.uuid4().hex[:8]}"
    sqs.send_message(QueueUrl=main_url, MessageBody=body)

    # AWS moves a message once ReceiveCount exceeds maxReceiveCount; the check asserts only that
    # it survives its first delivery, which avoids pinning an exact off-by-one boundary.
    receives = 0
    dlq_message = None
    for _ in range(8):
        resp = sqs.receive_message(QueueUrl=main_url, MaxNumberOfMessages=1, WaitTimeSeconds=1)
        got = resp.get("Messages", [])
        receives += len(got)
        for msg in got:
            sqs.change_message_visibility(
                QueueUrl=main_url, ReceiptHandle=msg["ReceiptHandle"], VisibilityTimeout=0
            )
        dresp = sqs.receive_message(QueueUrl=dlq_url, MaxNumberOfMessages=1, WaitTimeSeconds=1)
        if dresp.get("Messages"):
            dlq_message = dresp["Messages"][0]
            break

    if dlq_message is None:
        raise AssertionError("message never landed in the DLQ")
    if dlq_message["Body"] != body:
        raise AssertionError("DLQ message body mismatch")
    # Asserted after the loop because the loop breaks as soon as the DLQ holds the message.
    assert receives >= 2, (
        f"message reached the DLQ after {receives} delivery(ies); maxReceiveCount: 2 requires it to "
        f"survive at least the first"
    )
    _leftover = sqs.receive_message(
        QueueUrl=main_url, MaxNumberOfMessages=10, WaitTimeSeconds=1
    ).get("Messages", [])
    assert not _leftover, f"expected no messages, got {len(_leftover)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
