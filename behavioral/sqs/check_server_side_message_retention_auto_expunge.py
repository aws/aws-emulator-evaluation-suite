"""server-side-message-retention-auto-expunge."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "server-side-message-retention-auto-expunge"
GROUP = "server-side"
SERVICES = ["sqs"]

# MessageRetentionPeriod's documented minimum is 60 seconds (max 14 days):
# https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-basic-architecture.html
RETENTION_SECONDS = 60


# timing:real-time — retention: 60 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SetQueueAttributes.html
@tags("axis:negative-delivery", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """With the minimum MessageRetentionPeriod (60s), an unconsumed, never-deleted message is
    expunged once the period elapses: the approximate count reaches 0 and ReceiveMessage
    returns nothing."""
    sqs = ctx.client("sqs")
    body = "expire-me-without-being-deleted"
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-retain-"),
        Attributes={"MessageRetentionPeriod": str(RETENTION_SECONDS)},
        tags={"sim2real:managed": "true", "sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    sqs.send_message(QueueUrl=url, MessageBody=body)

    # Sanity: the message is actually there right after sending (never received/deleted).
    count = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]["ApproximateNumberOfMessages"]
    assert count == "1", f"expected the sent message to be present, saw count={count!r}"

    # Prove it is genuinely RECEIVABLE, not merely counted (VisibilityTimeout=0 so this
    # confirmation cannot hide the message behind its own visibility window).
    pre_msgs = sqs.receive_message(
        QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=1, VisibilityTimeout=0
    ).get("Messages", [])
    assert [m["Body"] for m in pre_msgs] == [body], (
        f"the message was counted but never receivable before expiry, so the disappearance "
        f"below would not prove retention: got {[m.get('Body') for m in pre_msgs]!r}"
    )

    # Poll (bounded, well past the 60s retention window) for the server-side expunge.
    _poll_until_expunged(ctx, url, timeout_s=180.0)


def _poll_until_expunged(ctx, url, timeout_s=180.0, interval_s=5.0):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        count = sqs.get_queue_attributes(
            QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"]
        )["Attributes"]["ApproximateNumberOfMessages"]
        if count == "0":
            # VisibilityTimeout=0: the confirmation read must never hide the message
            # behind its own visibility window and get misread as a permanent expunge
            # (the default queue VisibilityTimeout is 30s, well inside this poll's window).
            resp = sqs.receive_message(
                QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1, VisibilityTimeout=0
            )
            if not resp.get("Messages"):
                return
        time.sleep(interval_s)
    raise AssertionError(
        f"message was not auto-expunged within {timeout_s}s of a "
        f"{RETENTION_SECONDS}s MessageRetentionPeriod"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
