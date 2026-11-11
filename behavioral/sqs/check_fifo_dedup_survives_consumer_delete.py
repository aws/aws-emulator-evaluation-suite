"""fifo-dedup-survives-consumer-delete."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "fifo-dedup-survives-consumer-delete"
GROUP = "fifo"
SERVICES = ["sqs"]


def _receive_one(sqs, url, *, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2,
            MessageSystemAttributeNames=["MessageDeduplicationId", "SequenceNumber"],
        ).get("Messages", [])
        if msgs:
            return msgs[0]
    return None


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A FIFO dedup id stays claimed after the consumer deletes the message: a retry with the same
    id returns the original MessageId and SequenceNumber and is never delivered, while a new id is.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-dedupdel-") + ".fifo",
        Attributes={"FifoQueue": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    first = sqs.send_message(
        QueueUrl=url, MessageBody="charge-order-42", MessageGroupId="orders",
        MessageDeduplicationId="order-42",
    )
    got = _receive_one(sqs, url, timeout_s=30)
    assert got is not None and got["Body"] == "charge-order-42", (
        f"the first send was not delivered; received {got and got['Body']!r}"
    )
    assert got["Attributes"].get("MessageDeduplicationId") == "order-42", (
        f"received MessageDeduplicationId {got['Attributes'].get('MessageDeduplicationId')!r}"
    )
    sqs.delete_message(QueueUrl=url, ReceiptHandle=got["ReceiptHandle"])

    retry = sqs.send_message(
        QueueUrl=url, MessageBody="charge-order-42-retry", MessageGroupId="orders",
        MessageDeduplicationId="order-42",
    )
    assert retry["MessageId"] == first["MessageId"], (
        "a retry inside the dedup window must be acknowledged with the original MessageId, even "
        "after the original was consumed and deleted; the ids differ"
    )
    assert retry["SequenceNumber"] == first["SequenceNumber"], (
        "a retry inside the dedup window must echo the original SequenceNumber; got "
        f"{retry['SequenceNumber']!r} vs {first['SequenceNumber']!r}"
    )

    fresh = sqs.send_message(
        QueueUrl=url, MessageBody="charge-order-43", MessageGroupId="orders",
        MessageDeduplicationId="order-43",
    )
    assert int(fresh["SequenceNumber"]) > int(first["SequenceNumber"]), (
        f"a new deduplication id must get a later SequenceNumber: {fresh['SequenceNumber']!r} "
        f"after {first['SequenceNumber']!r}"
    )

    bodies: list[str] = []
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get(
            "Messages", []
        )
        if not msgs and bodies:
            break
        for m in msgs:
            bodies.append(m["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    assert bodies == ["charge-order-43"], (
        f"after the consumed message, only the new deduplication id may be delivered -- never the "
        f"retry; received {bodies!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
