"""receive-hides."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "receive-hides"
GROUP = 'visibility_dlq'
SERVICES = ['sqs']

@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A received message is in-flight: immediate second receive is empty."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    sqs.send_message(QueueUrl=url, MessageBody="receive-hides")
    received = []
    _seen = set()
    _idle = 0
    for _ in range(12):
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
        if len(received) >= 1:
            break
    if not received:
        raise AssertionError("no message received")
    _leftover = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1).get("Messages", [])
    assert not _leftover, f"expected no messages, got {len(_leftover)}"

    # Independent side-channel, at a genuinely different operation than ReceiveMessage:
    # the approximate not-visible counter must confirm the same in-flight state (direction
    # only — it is eventually consistent, so poll rather than trust a single read).
    _notvis = "0"
    _deadline = time.monotonic() + 20.0
    while time.monotonic() < _deadline:
        _attrs = sqs.get_queue_attributes(
            QueueUrl=url, AttributeNames=["ApproximateNumberOfMessagesNotVisible"]
        )["Attributes"]
        _notvis = _attrs.get("ApproximateNumberOfMessagesNotVisible", "0")
        if _notvis != "0":
            break
        time.sleep(1)
    assert int(_notvis) >= 1, (
        f"ApproximateNumberOfMessagesNotVisible stayed at {_notvis!r} while a message was in flight"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
