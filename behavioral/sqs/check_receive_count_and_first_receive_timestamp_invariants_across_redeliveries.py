"""receive-count-and-first-receive-timestamp-invariants-across-redeliveries."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "receive-count-and-first-receive-timestamp-invariants-across-redeliveries"
GROUP = 'invariants'
SERVICES = ['sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": "receive-count-timestamp-invariants"}

_DELIVERIES = 3


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Across three redeliveries of one message, ApproximateReceiveCount goes 1 -> 2 -> 3 while
    SentTimestamp and ApproximateFirstReceiveTimestamp stay identical, with SentTimestamp first.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_ReceiveMessage.html
    """
    sqs = ctx.client("sqs")
    marker = f"redelivery-marker-{uuid.uuid4().hex[:8]}"

    # VisibilityTimeout=2 so a redelivery is a couple of seconds away rather than minutes.
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"),
        Attributes={"VisibilityTimeout": "2"},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    sent = sqs.send_message(QueueUrl=url, MessageBody=marker)
    sent_id = sent["MessageId"]

    # The message is never deleted, so each visibility-timeout expiry redelivers it.
    deliveries = []
    deadline = time.monotonic() + 120
    while len(deliveries) < _DELIVERIES and time.monotonic() < deadline:
        batch = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2,
            AttributeNames=["All"], MessageSystemAttributeNames=["All"],
        ).get("Messages", [])
        deliveries += batch
    assert len(deliveries) == _DELIVERIES, (
        f"only {len(deliveries)} of {_DELIVERIES} deliveries of the same message arrived before "
        f"the deadline -- a message left un-deleted past its 2s VisibilityTimeout must be "
        f"redelivered: got {[d.get('Attributes', {}).get('ApproximateReceiveCount') for d in deliveries]!r}"
    )

    assert all(d["MessageId"] == sent_id for d in deliveries), (
        f"the three deliveries were not all the message that was sent ({sent_id!r}): "
        f"{[d['MessageId'] for d in deliveries]!r}"
    )

    # ApproximateReceiveCount is documented as approximate; with one producer and one consumer it
    # is exact, so a monotonic but non-consecutive sequence fails on purpose.
    counts = [int(d["Attributes"]["ApproximateReceiveCount"]) for d in deliveries]
    assert counts == [1, 2, 3], (
        f"ApproximateReceiveCount must increment exactly once per delivery: got {counts!r}, "
        f"expected [1, 2, 3]"
    )

    sent_stamps = {d["Attributes"]["SentTimestamp"] for d in deliveries}
    assert len(sent_stamps) == 1, (
        f"SentTimestamp changed between deliveries of the SAME message -- it records the enqueue "
        f"instant and cannot move: {[d['Attributes']['SentTimestamp'] for d in deliveries]!r}"
    )

    first_stamps = {d["Attributes"]["ApproximateFirstReceiveTimestamp"] for d in deliveries}
    assert len(first_stamps) == 1, (
        f"ApproximateFirstReceiveTimestamp must record the FIRST receive and never move: "
        f"{[d['Attributes']['ApproximateFirstReceiveTimestamp'] for d in deliveries]!r}"
    )

    sent_ms = int(sent_stamps.pop())
    first_recv_ms = int(first_stamps.pop())
    assert sent_ms <= first_recv_ms, (
        f"ApproximateFirstReceiveTimestamp ({first_recv_ms}) precedes SentTimestamp ({sent_ms}) "
        f"-- a message cannot be received before it was sent"
    )

    # Both are epoch milliseconds; a seconds value would pass every assertion above.
    assert len(str(sent_ms)) == 13, (
        f"SentTimestamp must be epoch milliseconds; {sent_ms!r} has {len(str(sent_ms))} digits"
    )
    assert len(str(first_recv_ms)) == 13, (
        f"ApproximateFirstReceiveTimestamp must be epoch milliseconds; {first_recv_ms!r} has "
        f"{len(str(first_recv_ms))} digits"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
