"""long-polling-returns-fast."""
from __future__ import annotations

import concurrent.futures
import threading
import time
import uuid

from behavioral_harness import tags

CHECK = "long-polling-returns-fast"
GROUP = 'state'
SERVICES = ['sqs']

@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A WaitTimeSeconds=5 long poll on an empty queue returns the message sent while it waits, before the wait ends.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_ReceiveMessage.html
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"),
        tags={"sim2real": "behavioral"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    body = f"longpoll-{uuid.uuid4().hex[:8]}"
    wait_time = 5
    dispatched = threading.Event()
    # Set as the ReceiveMessage request goes on the wire, so the send lands while the poll is open.
    sqs.meta.events.register_first("before-send.sqs.ReceiveMessage", lambda **kwargs: dispatched.set())

    def _receive():
        start = time.monotonic()
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=wait_time)
        return time.monotonic() - start, resp.get("Messages", [])

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(_receive)
        assert dispatched.wait(timeout=_budget_s(ctx, 10)), "the ReceiveMessage request was never dispatched"
        ctx.client("sqs").send_message(QueueUrl=url, MessageBody=body)
        elapsed, messages = future.result(timeout=_budget_s(ctx, wait_time + 30))

    # The queue is empty when the receive starts, so only a receive that is still waiting when the
    # send lands returns the message; returning it before WaitTimeSeconds is the documented wake.
    assert messages, "long poll did not return the message sent while it waited"
    assert messages[0]["Body"] == body, f"body mismatch: {messages[0]['Body']!r} != {body!r}"
    assert elapsed < wait_time, (
        f"long poll took {elapsed:.1f}s; a message that arrives mid-wait ends the poll before the "
        f"{wait_time}s WaitTimeSeconds"
    )


def _budget_s(ctx, cap_s):
    """A wait's timeout, bounded by the runner's remaining time so the wait fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
