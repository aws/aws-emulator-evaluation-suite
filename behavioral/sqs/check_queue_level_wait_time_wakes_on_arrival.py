"""queue-level-wait-time-wakes-on-arrival."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "queue-level-wait-time-wakes-on-arrival"
GROUP = "long-polling"
SERVICES = ["sqs"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A ReceiveMessage call with no WaitTimeSeconds inherits the queue's
    ReceiveMessageWaitTimeSeconds=20: it stays open on an empty queue and returns a message sent
    while it waits.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-short-and-long-polling.html
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-qlwt-"),
        Attributes={"ReceiveMessageWaitTimeSeconds": "20"},
        tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    dispatched = threading.Event()
    # Fire when the ReceiveMessage request actually goes on the wire, so the send below
    # is guaranteed to land while the poll is open rather than before it starts.
    sqs.meta.events.register_first("before-send.sqs.ReceiveMessage", lambda **kwargs: dispatched.set())

    def _receive():
        return sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1).get("Messages", [])

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(_receive)
        assert dispatched.wait(timeout=_budget_s(ctx, 10)), (
            "the ReceiveMessage request was never dispatched"
        )
        # A short poll on an empty queue answers at once with nothing; only the inherited long
        # poll is still open to return the message sent after the request went out.
        sqs.send_message(QueueUrl=url, MessageBody="wakes-queue-level-poller")
        messages = future.result(timeout=_budget_s(ctx, 40))

    assert messages, "the queue-level long poll returned no message"
    assert messages[0]["Body"] == "wakes-queue-level-poller", (
        f"unexpected body: {messages[0]['Body']!r}"
    )
    sqs.delete_message(QueueUrl=url, ReceiptHandle=messages[0]["ReceiptHandle"])

    drained = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2)
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
