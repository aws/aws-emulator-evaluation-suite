"""max-size-message-body-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "max-size-message-body-round-trip"
GROUP = "invariants"
SERVICES = ["sqs"]

MAX_BODY_BYTES = 262144  # 256 KiB, below the 1 MiB default MaximumMessageSize


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A 262144-byte (256 KiB) message body is accepted, stored and returned byte-for-byte
    unchanged (no silent truncation of a large body)."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-maxsz-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    # Single-byte ASCII repeated so character count == byte count.
    body = "x" * (MAX_BODY_BYTES - 1) + "y"
    assert len(body.encode("utf-8")) == MAX_BODY_BYTES, (
        f"test body is {len(body.encode('utf-8'))} bytes, expected exactly {MAX_BODY_BYTES}"
    )

    sqs.send_message(QueueUrl=url, MessageBody=body)

    received = _poll_for_message(ctx, url)
    assert len(received["Body"]) == MAX_BODY_BYTES, (
        f"received body is {len(received['Body'])} bytes, expected {MAX_BODY_BYTES} "
        "(possible silent truncation of a large body)"
    )
    assert received["Body"] == body, "received body content diverges from the sent body"
    sqs.delete_message(QueueUrl=url, ReceiptHandle=received["ReceiptHandle"])

    # Independent read: the deleted message must not still be deliverable.
    leftover = sqs.receive_message(
        QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2
    ).get("Messages", [])
    assert leftover == [], f"deleted message is still visible on the queue: {leftover}"


def _poll_for_message(ctx, url, timeout_s=30.0):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        msgs = resp.get("Messages", [])
        if msgs:
            return msgs[0]
    raise AssertionError("no message received within timeout")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
