"""fifo-concurrent-senders-preserve-per-sender-order."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "fifo-concurrent-senders-preserve-per-sender-order"
GROUP = "concurrency"
SERVICES = ["sqs"]

_TAGS = {"sim2real:managed": "true", "sim2real": CHECK}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Under concurrent senders to the same FIFO MessageGroupId, each sender's own send order is preserved."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + ".fifo",
        Attributes={
            "FifoQueue": "true",
            "ContentBasedDeduplication": "true",
            # keep messages safely in-flight for the whole test so none are redelivered
            # (which would otherwise appear as duplicate entries and look like reordering).
            "VisibilityTimeout": "180",
        },
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    num_threads = 4
    per_thread = 5

    def _sender(thread_id: int) -> None:
        for i in range(per_thread):
            sqs.send_message(
                QueueUrl=url, MessageBody=f"t{thread_id}-{i}", MessageGroupId="shared-group"
            )

    with ThreadPoolExecutor(max_workers=num_threads) as pool:
        list(pool.map(_sender, range(num_threads)))

    received = []
    deadline = time.monotonic() + 60.0
    expected_total = num_threads * per_thread
    while len(received) < expected_total and time.monotonic() < deadline:
        batch = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5).get("Messages", [])
        received.extend(batch)
        # FIFO queues only make further messages in a group visible once the previously
        # received (but undeleted) ones for that group are deleted or expire, so delete
        # as we go instead of waiting until the very end to collect everything.
        for m in batch:
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    assert len(received) == expected_total, f"expected {expected_total} messages, got {len(received)}"

    bodies_in_order = [m["Body"] for m in received]
    for thread_id in range(num_threads):
        own_sequence = [b for b in bodies_in_order if b.startswith(f"t{thread_id}-")]
        expected = [f"t{thread_id}-{i}" for i in range(per_thread)]
        assert own_sequence == expected, f"thread {thread_id} order violated: {own_sequence}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

