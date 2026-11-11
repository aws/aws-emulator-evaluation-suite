"""e2e-delay-queue-then-consume."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "e2e-delay-queue-then-consume"
GROUP = "e2e_workflows"
SERVICES = ["sqs"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A message sent to a DelaySeconds queue is invisible to consumers until the
    delay elapses, and is then consumable exactly once end-to-end."""
    sqs = ctx.client("sqs")
    delay_seconds = 8
    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-delayq-"),
        Attributes={"DelaySeconds": str(delay_seconds)},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))

    body = f"delayed-{queue_url}"
    send_time = time.monotonic()
    sqs.send_message(QueueUrl=queue_url, MessageBody=body)

    # Invariant: the message must not be visible before the delay elapses.
    while time.monotonic() - send_time < delay_seconds - 2.0:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=1)
        assert not resp.get("Messages"), "message became visible before DelaySeconds elapsed"

    # Now poll (bounded) until it does become visible and consume it exactly once.
    received = None
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline and received is None:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        msgs = resp.get("Messages", [])
        if msgs:
            received = msgs[0]
    assert received is not None, "delayed message never became visible"
    assert received["Body"] == body
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=received["ReceiptHandle"])

    # confirm it is gone for good (no re-delivery after delete)
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=2)
        assert not resp.get("Messages"), "deleted message reappeared"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
