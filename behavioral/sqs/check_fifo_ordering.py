"""fifo-ordering."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "fifo-ordering"
GROUP = 'fifo'
SERVICES = ['sqs']

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """FIFO messages in one group are received in send order."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + ".fifo",
        Attributes={"FifoQueue": "true"},
        tags={"sim2real:managed": "true", "sim2real": "fifo-ordering"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    token = uuid.uuid4().hex[:8]
    group = "sim2real-group"
    bodies = [f"fifo-order-{i}-{token}" for i in range(3)]
    for i, body in enumerate(bodies):
        sqs.send_message(
            QueueUrl=url,
            MessageBody=body,
            MessageGroupId=group,
            MessageDeduplicationId=f"{token}-{i}",
        )
    received = []
    _seen = set()
    _idle = 0
    for _ in range(15):
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
        if len(received) >= 3:
            break
    got = [m["Body"] for m in received]
    assert got == bodies, f"FIFO order mismatch: sent {bodies}, received {got}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
