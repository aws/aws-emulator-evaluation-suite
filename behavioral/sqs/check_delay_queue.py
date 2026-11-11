"""delay-queue."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "delay-queue"
GROUP = 'state'
SERVICES = ['sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": "delay-queue"}

# timing:real-time — visibility: 2 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-delay-queues.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Queue with DelaySeconds=2: immediate receive is empty, after delay message arrives."""
    sqs = ctx.client("sqs")
    delay_seconds = 2
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"),
        Attributes={"DelaySeconds": str(delay_seconds)},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    body = f"delay-queue-{uuid.uuid4().hex[:8]}"
    send_time = time.monotonic()
    sqs.send_message(QueueUrl=url, MessageBody=body)
    # Immediate receive should be empty (message is delayed)
    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=0)
    messages = resp.get("Messages", [])
    if messages:
        raise AssertionError(f"expected no messages immediately after send to delay queue, got {messages!r}")

    # Bounded retry for the delay to expire — deadline is the declared DelaySeconds plus a margin
    # for SQS's own delivery latency, never an unconditional sleep.
    deadline = send_time + delay_seconds + 15
    received = []
    seen = set()
    while time.monotonic() < deadline and not received:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=1)
        msgs = resp.get("Messages", [])
        for m in msgs:
            if m["MessageId"] not in seen:
                seen.add(m["MessageId"])
                received.append(m)
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    elapsed = time.monotonic() - send_time
    if not received:
        raise AssertionError(f"message never arrived after {elapsed:.1f}s waiting on a {delay_seconds}s delay queue")
    if elapsed < delay_seconds:
        raise AssertionError(
            f"message became visible after only {elapsed:.1f}s, before DelaySeconds={delay_seconds} could have elapsed"
        )
    if received[0]["Body"] != body:
        raise AssertionError(f"body mismatch: {received[0]['Body']!r} != {body!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
