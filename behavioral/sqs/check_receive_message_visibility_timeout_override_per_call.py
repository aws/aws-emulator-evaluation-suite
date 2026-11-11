"""receive-message-visibility-timeout-override-per-call."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "receive-message-visibility-timeout-override-per-call"
GROUP = "lifecycle"
SERVICES = ["sqs"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ReceiveMessage's own VisibilityTimeout parameter overrides the queue's default for that receipt."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"), Attributes={"VisibilityTimeout": "60"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    message_id = sqs.send_message(QueueUrl=url, MessageBody="override-my-visibility")["MessageId"]

    # Override the 60s queue default down to 3s for this one receipt.
    received = _poll_until(
        lambda: sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=5, VisibilityTimeout=3
        ).get("Messages", []),
        lambda msgs: len(msgs) == 1,
        timeout_s=20.0,
    )[0]
    assert received["MessageId"] == message_id, (
        f"expected to receive {message_id!r}, got {received.get('MessageId')!r}"
    )

    # The override must actually HIDE the message -- an independent read taken right after
    # receipt must not see it. Without this, a target that ignores VisibilityTimeout entirely
    # (always returns the message) would still pass the reappearance check below.
    still_hidden = sqs.receive_message(
        QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=0
    ).get("Messages", [])
    assert not any(m["MessageId"] == message_id for m in still_hidden), (
        f"expected {message_id} hidden immediately after a 3s VisibilityTimeout receipt, "
        f"got it back in {still_hidden!r}"
    )

    # Well before the queue's 60s default would elapse, the per-call 3s override must have expired.
    reappeared = _poll_until(
        lambda: sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2).get("Messages", []),
        lambda msgs: any(m["MessageId"] == message_id for m in msgs),
        timeout_s=15.0,
    )
    msg = next(m for m in reappeared if m["MessageId"] == message_id)
    sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])


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
