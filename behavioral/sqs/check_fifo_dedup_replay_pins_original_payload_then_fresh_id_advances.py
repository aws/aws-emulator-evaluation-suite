"""fifo-dedup-replay-pins-original-payload-then-fresh-id-advances."""
from __future__ import annotations

import hashlib

from behavioral_harness import tags

CHECK = "fifo-dedup-replay-pins-original-payload-then-fresh-id-advances"
GROUP = "fifo"
SERVICES = ["sqs"]


def _drain(sqs, url, *, max_messages: int, idle_rounds: int = 3):
    """Unique messages seen over repeated receives, stopping after ``idle_rounds`` empty polls."""
    seen_ids: set[str] = set()
    messages: list[dict] = []
    idle = 0
    while True:
        resp = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2, MessageAttributeNames=["All"]
        )
        msgs = resp.get("Messages", [])
        if not msgs:
            idle += 1
            if idle >= idle_rounds:
                return messages
            continue
        idle = 0
        for m in msgs:
            if m["MessageId"] not in seen_ids:
                seen_ids.add(m["MessageId"])
                messages.append(m)
        if len(messages) >= max_messages:
            return messages


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A FIFO dedup replay against a still-queued message echoes the first send's MessageId and
    SequenceNumber with the replayed body's own MD5, and delivery still carries only the first
    send's payload. A fresh deduplication id then mints a new, greater SequenceNumber and delivers.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-dedupreplay-") + ".fifo",
        Attributes={"FifoQueue": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    group = "orders"
    dedup_1 = "order-7001"
    body_1 = "charge-order-7001-v1"
    body_2 = "charge-order-7001-v2"

    first = sqs.send_message(
        QueueUrl=url,
        MessageBody=body_1,
        MessageGroupId=group,
        MessageDeduplicationId=dedup_1,
        MessageAttributes={"status": {"DataType": "String", "StringValue": "pending"}},
    )
    second = sqs.send_message(
        QueueUrl=url,
        MessageBody=body_2,
        MessageGroupId=group,
        MessageDeduplicationId=dedup_1,
        MessageAttributes={"status": {"DataType": "String", "StringValue": "shipped"}},
    )
    assert second["MessageId"] == first["MessageId"], (
        f"dedup replay MessageId {second['MessageId']!r} != original {first['MessageId']!r}"
    )
    assert second["SequenceNumber"] == first["SequenceNumber"], (
        f"dedup replay SequenceNumber {second['SequenceNumber']!r} != original "
        f"{first['SequenceNumber']!r}"
    )
    expected_md5_2 = hashlib.md5(body_2.encode("utf-8")).hexdigest()
    assert second["MD5OfMessageBody"] == expected_md5_2, (
        f"dedup replay MD5OfMessageBody {second['MD5OfMessageBody']!r} != md5 of the replayed "
        f"body {expected_md5_2!r}"
    )

    delivered = _drain(sqs, url, max_messages=1)
    assert len(delivered) == 1, f"expected exactly 1 delivered message, got {len(delivered)}"
    msg = delivered[0]
    expected_md5_1 = hashlib.md5(body_1.encode("utf-8")).hexdigest()
    assert msg["MessageId"] == first["MessageId"], (
        f"delivered MessageId {msg['MessageId']!r} != first send's {first['MessageId']!r}"
    )
    assert msg["Body"] == body_1, f"delivered body {msg['Body']!r} != first send's body {body_1!r}"
    assert msg["MD5OfBody"] == expected_md5_1, (
        f"delivered MD5OfBody {msg['MD5OfBody']!r} != md5 of the first send's body {expected_md5_1!r}"
    )
    status = msg.get("MessageAttributes", {}).get("status", {}).get("StringValue")
    assert status == "pending", (
        f"delivered attribute status={status!r} != first send's 'pending' "
        "(the replay's attribute must never overwrite the stored message)"
    )
    sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])

    dedup_3 = "order-7002"
    body_3 = "charge-order-7002-v1"
    third = sqs.send_message(
        QueueUrl=url,
        MessageBody=body_3,
        MessageGroupId=group,
        MessageDeduplicationId=dedup_3,
        MessageAttributes={"status": {"DataType": "String", "StringValue": "pending"}},
    )
    assert third["MessageId"] != first["MessageId"], (
        "a fresh deduplication id must mint a new MessageId, but it echoed the first send's"
    )
    assert int(third["SequenceNumber"]) > int(first["SequenceNumber"]), (
        f"a fresh deduplication id must get a greater SequenceNumber: {third['SequenceNumber']!r} "
        f"is not greater than {first['SequenceNumber']!r}"
    )

    after_delete = _drain(sqs, url, max_messages=1)
    assert len(after_delete) == 1, (
        f"after deleting the first message, expected only the fresh deduplication id's message "
        f"to be delivered, got {len(after_delete)}"
    )
    fresh_msg = after_delete[0]
    assert fresh_msg["MessageId"] == third["MessageId"], (
        f"delivered MessageId {fresh_msg['MessageId']!r} != fresh send's {third['MessageId']!r} "
        "(no leftover message from the deleted dedup group was still queued)"
    )
    assert fresh_msg["Body"] == body_3, (
        f"delivered body {fresh_msg['Body']!r} != fresh send's body {body_3!r}"
    )
    sqs.delete_message(QueueUrl=url, ReceiptHandle=fresh_msg["ReceiptHandle"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
