"""message-timer."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "message-timer"
GROUP = 'state'
SERVICES = ['sqs']

_DELAY_S = 2
_TAGS = {"sim2real:managed": "true", "sim2real": "message-timer"}


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Per-message DelaySeconds=2: immediate receive empty, arrives after delay."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    body = f"msg-timer-{uuid.uuid4().hex[:8]}"
    sqs.send_message(QueueUrl=url, MessageBody=body, DelaySeconds=_DELAY_S)
    # Immediate receive should be empty: the delay has not elapsed yet.
    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=0)
    messages = resp.get("Messages", [])
    if messages:
        raise AssertionError("expected no messages immediately with per-message delay")
    # Bounded retry until the delay has elapsed — no unconditional sleep; each poll's own
    # long-poll wait is itself bounded, and the deadline covers >=3x the declared delay.
    deadline = time.monotonic() + max(3 * _DELAY_S, 10)
    received = []
    _seen = set()
    while time.monotonic() < deadline and not received:
        _resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2)
        for _m in _resp.get("Messages", []):
            if _m["MessageId"] not in _seen:
                _seen.add(_m["MessageId"])
                received.append(_m)
            sqs.delete_message(QueueUrl=url, ReceiptHandle=_m["ReceiptHandle"])
    if not received:
        raise AssertionError(
            f"message never arrived after per-message delay ({_DELAY_S}s) expired, "
            f"within a {max(3 * _DELAY_S, 10)}s bounded retry window"
        )
    if received[0]["Body"] != body:
        raise AssertionError(f"body mismatch: {received[0]['Body']!r} != {body!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
