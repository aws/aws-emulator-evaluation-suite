"""fifo-exactly-once-multiple-sends."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "fifo-exactly-once-multiple-sends"
GROUP = 'fifo'
SERVICES = ['sqs']

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Send same dedup ID 5 times rapidly. Every send must report the same MessageId, and exactly 1 message is ever delivered."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + ".fifo",
        Attributes={"FifoQueue": "true"},
        tags={"sim2real-behav": "fifo-exactly-once-multiple-sends"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    token = uuid.uuid4().hex[:8]
    group = "sim2real-group"
    dedup_id = f"{token}-multi-dedup"
    body = f"fifo-multi-{token}"
    send_ids = []
    for _ in range(5):
        _resp = sqs.send_message(
            QueueUrl=url,
            MessageBody=body,
            MessageGroupId=group,
            MessageDeduplicationId=dedup_id,
        )
        send_ids.append(_resp["MessageId"])
    assert len(set(send_ids)) == 1, (
        f"expected all 5 duplicate sends to report the same MessageId, got {sorted(set(send_ids))}"
    )
    received = []
    _seen = set()
    _idle = 0
    for _ in range(10):
        _resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
        _msgs = _resp.get("Messages", [])
        if not _msgs:
            _idle += 1
            if received and _idle >= 3:
                break
            continue
        _idle = 0
        for _m in _msgs:
            if _m["MessageId"] not in _seen:
                _seen.add(_m["MessageId"])
                received.append(_m)
            sqs.delete_message(QueueUrl=url, ReceiptHandle=_m["ReceiptHandle"])
        if len(received) >= 5:
            break
    assert len(received) == 1, f"expected 1 message after 5 dedup sends, got {len(received)}"
    assert received[0]["MessageId"] == send_ids[0], (
        f"delivered MessageId {received[0]['MessageId']!r} does not match the id "
        f"SendMessage reported for the deduplicated group, {send_ids[0]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
