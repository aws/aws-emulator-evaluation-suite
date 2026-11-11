"""delete-message-batch."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "delete-message-batch"
GROUP = 'state'
SERVICES = ['sqs']

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteMessageBatch removes multiple messages in one call; queue ends empty."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    token = uuid.uuid4().hex[:8]
    entries = [{"Id": str(i), "MessageBody": f"delbatch-{i}-{token}"} for i in range(1, 4)]
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
        if len(received) >= 3:
            break
    if len(received) != 3:
        raise AssertionError(f"expected 3 messages to delete, got {len(received)}")
    del_entries = [
        {"Id": str(i), "ReceiptHandle": m["ReceiptHandle"]} for i, m in enumerate(received)
    ]
    resp = sqs.delete_message_batch(QueueUrl=url, Entries=del_entries)
    if resp.get("Failed"):
        raise AssertionError(f"DeleteMessageBatch failures: {resp['Failed']}")
    _leftover = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1).get("Messages", [])
    assert not _leftover, f"expected no messages, got {len(_leftover)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
