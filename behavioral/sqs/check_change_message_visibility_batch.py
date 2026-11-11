"""change-message-visibility-batch."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "change-message-visibility-batch"
GROUP = 'visibility_dlq'
SERVICES = ['sqs']

@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ChangeMessageVisibilityBatch(VT=0) re-exposes multiple in-flight messages at once."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    token = uuid.uuid4().hex[:8]
    entries = [{"Id": str(i), "MessageBody": f"cmvbatch-{i}-{token}"} for i in range(1, 3)]
    sqs.send_message_batch(QueueUrl=url, Entries=entries)
    received = []
    _seen = set()
    _idle = 0
    for _ in range(15):
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
        if len(received) >= 2:
            break
    assert len(received) == 2, f"expected 2 messages, got {len(received)}"
    cmv_entries = [
        {"Id": str(i), "ReceiptHandle": m["ReceiptHandle"], "VisibilityTimeout": 0}
        for i, m in enumerate(received)
    ]
    resp = sqs.change_message_visibility_batch(QueueUrl=url, Entries=cmv_entries)
    assert not resp.get("Failed"), f"ChangeMessageVisibilityBatch failures: {resp.get('Failed')}"
    again = []
    _seen = set()
    _idle = 0
    for _ in range(15):
        _resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
        _msgs = _resp.get("Messages", [])
        if not _msgs:
            _idle += 1
            if again and _idle >= 3:
                break
            continue
        _idle = 0
        for _m in _msgs:
            if _m["MessageId"] not in _seen:
                _seen.add(_m["MessageId"])
                again.append(_m)
            sqs.delete_message(QueueUrl=url, ReceiptHandle=_m["ReceiptHandle"])
        if len(again) >= 2:
            break
    assert len(again) == 2, f"expected 2 re-exposed messages, got {len(again)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
