"""delete-message-stale-receipt-handle-after-redelivery-succeeds."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-message-stale-receipt-handle-after-redelivery-succeeds"
GROUP = "delete-semantics"
SERVICES = ["sqs"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A redelivered message carries a new receipt handle, and DeleteMessage with the handle from
    its first receive still succeeds rather than being refused as invalid.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_DeleteMessage.html
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-stale-"),
        Attributes={"VisibilityTimeout": "2"},
        tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    sent_id = sqs.send_message(QueueUrl=url, MessageBody="stale-handle-probe")["MessageId"]
    first = _poll_for_message(sqs, url, sent_id, timeout_s=_budget_s(ctx, 30.0))
    first_handle = first["ReceiptHandle"]

    # The 2 s visibility timeout lapses, so the same message is redelivered under a new handle.
    second = _poll_for_message(sqs, url, sent_id, timeout_s=_budget_s(ctx, 30.0))
    second_handle = second["ReceiptHandle"]
    assert second_handle != first_handle, (
        f"the redelivery of {sent_id!r} reused its first receipt handle {first_handle!r}"
    )

    # AWS documents only that the call succeeds; whether it deletes the message is not promised.
    resp = sqs.delete_message(QueueUrl=url, ReceiptHandle=first_handle)
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, (
        f"DeleteMessage with the first-receive handle of a redelivered message answered HTTP "
        f"{status!r}, expected 200"
    )


def _poll_for_message(sqs, url, message_id, timeout_s):
    """Receive until the message `message_id` is delivered; return it."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2)
        for msg in resp.get("Messages", []):
            if msg["MessageId"] == message_id:
                return msg
    raise TimeoutError(f"message {message_id!r} was not delivered within {timeout_s:.0f}s")


def _budget_s(ctx, cap_s):
    """A wait's timeout, bounded by the runner's remaining time so the wait fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
