"""batch-send-receive-count."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "batch-send-receive-count"
GROUP = 'state'
SERVICES = ['sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": "batch-send-receive-count"}

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendMessageBatch(3) → all three distinct bodies are receivable."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    token = uuid.uuid4().hex[:8]
    entries = [{"Id": str(i), "MessageBody": f"batch-{i}-{token}"} for i in range(1, 4)]
    resp = sqs.send_message_batch(QueueUrl=url, Entries=entries)
    assert not resp.get("Failed"), f"SendMessageBatch failures: {resp.get('Failed')}"
    expected = {e["MessageBody"] for e in entries}
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
            sqs.delete_message(QueueUrl=url, ReceiptHandle=_m["ReceiptHandle"])
        if len(received) >= 3:
            break
    got = {m["Body"] for m in received}
    assert got == expected, f"expected {sorted(expected)}, got {sorted(got)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
