"""message-retention-period-expires-old-messages."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "message-retention-period-expires-old-messages"
GROUP = "lifecycle"
SERVICES = ["sqs"]


# timing:real-time — retention: 60 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SetQueueAttributes.html
@tags("axis:negative-delivery", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A message outlives its queue's MessageRetentionPeriod and is permanently discarded (never delivered again)."""
    sqs = ctx.client("sqs")
    # MessageRetentionPeriod=60 is the documented minimum; set at CREATE time so it applies
    # immediately (changing it later on an existing queue can take up to 15 minutes to
    # propagate per AWS docs, which this check avoids).
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"),
        Attributes={"MessageRetentionPeriod": "60"},
        tags={"sim2real:managed": "true", "sim2real": "message-retention-period-expiry"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    sent_at = time.monotonic()
    message_id = sqs.send_message(QueueUrl=url, MessageBody="ephemeral-message")["MessageId"]

    # Confirm it is initially receivable (sanity, not the assertion under test).
    initial = _poll_until(
        lambda: sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=5).get("Messages", []),
        lambda msgs: any(m["MessageId"] == message_id for m in msgs),
        timeout_s=15.0,
    )
    handle = next(m for m in initial if m["MessageId"] == message_id)["ReceiptHandle"]
    # Immediately release it back to the queue so it can expire from a "stored" state.
    sqs.change_message_visibility(QueueUrl=url, ReceiptHandle=handle, VisibilityTimeout=0)

    # Poll (bounded, generously past the 60s retention window) for the message to be gone for good.
    # A single empty ReceiveMessage is not proof of permanent absence -- SQS is a distributed queue
    # and can transiently return no messages for one that is still there. Require several
    # consecutive clean reads (empty receive AND both counters at zero) before concluding expiry,
    # the same freeze-detector guard used elsewhere against this exact flake.
    CONSECUTIVE_CLEAN_REQUIRED = 3
    consecutive_clean = 0
    deadline = sent_at + 160.0
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=3)
        if any(m["MessageId"] == message_id for m in resp.get("Messages", [])):
            consecutive_clean = 0
            time.sleep(2)
            continue
        attrs = sqs.get_queue_attributes(
            QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"]
        )["Attributes"]
        if attrs["ApproximateNumberOfMessages"] == "0" and attrs["ApproximateNumberOfMessagesNotVisible"] == "0":
            consecutive_clean += 1
            if consecutive_clean >= CONSECUTIVE_CLEAN_REQUIRED:
                return
        else:
            consecutive_clean = 0
        time.sleep(3)
    raise AssertionError(
        f"message was not expired by the retention period within the expected window "
        f"(last consecutive_clean={consecutive_clean})"
    )


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
