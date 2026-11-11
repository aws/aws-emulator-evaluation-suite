"""fifo-content-based-dedup."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "fifo-content-based-dedup"
GROUP = 'fifo'
SERVICES = ['sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": "fifo-content-based-dedup"}

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ContentBasedDeduplication: two sends of the same body (no dedup id) → ONE message."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + ".fifo",
        Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true"},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    token = uuid.uuid4().hex[:8]
    body = f"cbd-{token}"
    group = "sim2real-group"
    sends = [sqs.send_message(QueueUrl=url, MessageBody=body, MessageGroupId=group) for _ in range(2)]
    if sends[1]["MessageId"] != sends[0]["MessageId"]:
        raise AssertionError(
            f"content-based dedup broken: identical resend minted a new MessageId "
            f"{sends[1]['MessageId']} instead of echoing {sends[0]['MessageId']}"
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
        if len(received) >= 2:
            break
    if len(received) != 1:
        raise AssertionError(f"expected 1 message after content-based dedup, got {len(received)}")
    if received[0]["MessageId"] != sends[0]["MessageId"]:
        raise AssertionError(
            f"delivered MessageId {received[0]['MessageId']} != the retained send's "
            f"{sends[0]['MessageId']}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
