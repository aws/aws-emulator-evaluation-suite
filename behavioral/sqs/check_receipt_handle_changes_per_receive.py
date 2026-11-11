"""receipt-handle-changes-per-receive."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "receipt-handle-changes-per-receive"
GROUP = "invariants"
SERVICES = ["sqs"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """After a message's visibility timeout expires and it becomes receivable again, the
    redelivery carries a distinct receipt handle -- SQS never reuses a receipt handle across
    separate receives of the same message."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-rh-"),
        Attributes={"VisibilityTimeout": "2"},
        tags={"sim2real:managed": "true", "sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    sqs.send_message(QueueUrl=url, MessageBody="receipt-handle-test")

    first = _poll_for_message(ctx, url, timeout_s=30.0)
    first_handle = first["ReceiptHandle"]
    first_id = first["MessageId"]

    # Do not delete -- let the 2s visibility timeout expire and wait for redelivery.
    second = _poll_for_redelivery(ctx, url, expected_message_id=first_id, timeout_s=30.0)
    second_handle = second["ReceiptHandle"]

    assert second_handle != first_handle, (
        f"receipt handle was reused across separate receives: first={first_handle!r} "
        f"second={second_handle!r}"
    )
    sqs.delete_message(QueueUrl=url, ReceiptHandle=second_handle)

    remainder = _drain(ctx, url, timeout_s=8.0)
    assert not remainder, (
        f"message {first_id!r} still deliverable after delete_message with the "
        f"current receipt handle: got {remainder!r}"
    )


def _poll_for_message(ctx, url, timeout_s=30.0):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        msgs = resp.get("Messages", [])
        if msgs:
            return msgs[0]
    raise AssertionError("no message received within timeout")


def _poll_for_redelivery(ctx, url, expected_message_id, timeout_s=30.0):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            if msg["MessageId"] == expected_message_id:
                return msg
        time.sleep(0.5)
    raise AssertionError("message was never redelivered after visibility timeout expiry")


def _drain(ctx, url, timeout_s):
    """Poll for the full window and return every message seen -- used to prove absence
    (a deleted message must not come back), never to prove presence."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    seen = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        seen.extend(resp.get("Messages", []))
    return seen


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
