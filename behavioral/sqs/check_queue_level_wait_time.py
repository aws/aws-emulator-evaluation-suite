"""queue-level-wait-time."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "queue-level-wait-time"
GROUP = 'state'
SERVICES = ['sqs']

# timing:real-time — lease: 2 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-short-and-long-polling.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Queue-level ReceiveMessageWaitTimeSeconds drives long polling with no per-call param.

    A receive that passes NO WaitTimeSeconds must inherit the queue attribute and
    block. Catches emulators that only honor the per-request WaitTimeSeconds.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"),
        Attributes={"ReceiveMessageWaitTimeSeconds": "2"},
        tags={"sim2real": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    start = time.monotonic()
    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1)
    elapsed = time.monotonic() - start
    if resp.get("Messages"):
        raise AssertionError("expected empty receive on an empty queue")
    if elapsed < 1.5:
        raise AssertionError(
            f"receive returned in {elapsed:.3f}s; queue-level "
            f"ReceiveMessageWaitTimeSeconds=2 was not honored"
        )
    # elapsed-bound: the queue's ReceiveMessageWaitTimeSeconds=2 bounds the long poll; the ceiling is the claim.
    if elapsed > 6.0:
        raise AssertionError(
            f"receive returned in {elapsed:.3f}s; queue-level "
            f"ReceiveMessageWaitTimeSeconds=2 should bound the wait, not hang well past it"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
