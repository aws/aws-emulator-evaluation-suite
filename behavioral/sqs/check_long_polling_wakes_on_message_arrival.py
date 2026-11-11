"""long-polling-wakes-on-message-arrival."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "long-polling-wakes-on-message-arrival"
GROUP = "data-plane"
SERVICES = ["sqs"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A long-poll ReceiveMessage returns the message sent while it waits before WaitTimeSeconds ends,
    and DeleteMessage then removes it from the queue.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_ReceiveMessage.html
    """
    sqs = ctx.client("sqs")
    queue_name = ctx.unique_name("sim2real-sqs-longpoll-")
    url = sqs.create_queue(
        QueueName=queue_name, tags={"sim2real-check": "long-polling-wakes-on-message-arrival"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    wait_time = 18
    request_dispatched = threading.Event()
    # Fire when the ReceiveMessage HTTP request is actually about to go over the
    # wire, not merely when the pool thread starts running — the latter races the
    # sender: a thread that has started but not yet dispatched its request lets
    # send_message land before AWS ever sees an open long-poll, which would make
    # this pass on the trivial "message already there" case instead of on a real
    # mid-wait wakeup.
    sqs.meta.events.register_first(
        "before-send.sqs.ReceiveMessage", lambda **kwargs: request_dispatched.set()
    )

    def _long_poll():
        start = time.monotonic()
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=wait_time)
        return time.monotonic() - start, resp.get("Messages", [])

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(_long_poll)
        assert request_dispatched.wait(timeout=_budget_s(ctx, 10)), (
            "long-poll thread never dispatched its ReceiveMessage request"
        )
        sqs.send_message(QueueUrl=url, MessageBody="wake-up-the-long-poller")
        elapsed, messages = future.result(timeout=_budget_s(ctx, wait_time + 30))

    assert messages, "long poll returned no message at all"
    assert messages[0]["Body"] == "wake-up-the-long-poller", (
        f"unexpected body: {messages[0]['Body']!r}"
    )
    sqs.delete_message(QueueUrl=url, ReceiptHandle=messages[0]["ReceiptHandle"])

    # A poll that only returns once the full window elapses takes at least WaitTimeSeconds.
    assert elapsed < wait_time, (
        f"long poll took {elapsed:.1f}s (>= WaitTimeSeconds {wait_time}), so it slept the full "
        f"window instead of waking up when the message arrived"
    )

    # independent read: the delete actually removed it, not just the local handle
    drained = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=0)
    assert not drained.get("Messages"), (
        f"queue still has a message after delete_message: {drained.get('Messages')}"
    )


def _budget_s(ctx, cap_s):
    """A wait's timeout, bounded by the runner's remaining time so the wait fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
