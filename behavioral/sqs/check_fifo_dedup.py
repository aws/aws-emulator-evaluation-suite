"""fifo-dedup."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "fifo-dedup"
GROUP = 'fifo'
SERVICES = ['sqs']

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two sends with same MessageDeduplicationId yield ONE message."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-") + ".fifo", Attributes={"FifoQueue": "true"})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    token = uuid.uuid4().hex[:8]
    group = "sim2real-group"
    dedup_id = f"{token}-dedup"
    for _ in range(2):
        sqs.send_message(
            QueueUrl=url,
            MessageBody=f"fifo-dedup-{token}",
            MessageGroupId=group,
            MessageDeduplicationId=dedup_id,
        )
    received = []
    _seen = set()
    _idle = 0
    for _ in range(10):
        _resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=1)
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
        if len(received) >= 2:
            break
    assert len(received) == 1, f"expected 1 after dedup, got {len(received)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
