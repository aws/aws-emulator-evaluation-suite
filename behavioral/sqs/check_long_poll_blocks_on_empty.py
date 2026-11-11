"""long-poll-blocks-on-empty."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "long-poll-blocks-on-empty"
GROUP = 'state'
SERVICES = ['sqs']

# timing:real-time — lease: 2 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-short-and-long-polling.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """ReceiveMessage(WaitTimeSeconds=2) on an empty queue blocks for about 2s and returns no
    messages, proving the long-poll wait actually happens."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    start = time.monotonic()
    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2)
    elapsed = time.monotonic() - start
    if resp.get("Messages"):
        raise AssertionError("expected empty receive on an empty queue")
    if elapsed < 1.5:
        raise AssertionError(
            f"long poll returned in {elapsed:.3f}s; did not block for WaitTimeSeconds=2 "
            f"(emulator likely ignores long polling)"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
