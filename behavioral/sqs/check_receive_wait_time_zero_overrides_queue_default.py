"""receive-wait-time-zero-overrides-queue-default."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait

from behavioral_harness import tags

CHECK = "receive-wait-time-zero-overrides-queue-default"
GROUP = "long-polling"
SERVICES = ["sqs"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ReceiveMessage(WaitTimeSeconds=0) on an empty queue whose ReceiveMessageWaitTimeSeconds is 20
    is a short poll: it answers empty and does not pick up a message sent after it went out.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_ReceiveMessage.html
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-rwz-"),
        Attributes={"ReceiveMessageWaitTimeSeconds": "20"},
        tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    dispatched = threading.Event()
    # Fire when the ReceiveMessage request goes on the wire, so the send below follows it.
    sqs.meta.events.register_first(
        "before-send.sqs.ReceiveMessage", lambda **kwargs: dispatched.set()
    )

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            lambda: sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=0)
        )
        assert dispatched.wait(timeout=_budget_s(ctx, 10)), (
            "the ReceiveMessage request was never dispatched"
        )
        # A short poll has answered by now; one that fell back to the queue's 20 s long poll is
        # still open and returns the message sent next.
        wait([future], timeout=_budget_s(ctx, 10))
        body = "sent-after-the-short-poll"
        sqs.send_message(QueueUrl=url, MessageBody=body)
        messages = future.result(timeout=_budget_s(ctx, 40)).get("Messages", [])

    assert not messages, (
        f"ReceiveMessage(WaitTimeSeconds=0) returned {messages!r}: it waited on the queue's 20 s "
        f"ReceiveMessageWaitTimeSeconds instead of answering as a short poll"
    )

    # Positive control: the message sent after the short poll is on the queue.
    received = []
    deadline = time.monotonic() + _budget_s(ctx, 30)
    while not received and time.monotonic() < deadline:
        received = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2
        ).get("Messages", [])
    if not received:
        raise TimeoutError(f"the message {body!r} was never received from the queue")
    assert received[0]["Body"] == body, f"unexpected body: {received[0]['Body']!r}"


def _budget_s(ctx, cap_s):
    """A wait's timeout, bounded by the runner's remaining time so the wait fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
