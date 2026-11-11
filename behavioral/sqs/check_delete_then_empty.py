"""delete-then-empty."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-then-empty"
GROUP = 'state'
SERVICES = ['sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": "delete-then-empty"}

# Deliberately short so the check's own runtime, not the queue's 30s default, bounds how
# long we have to wait for the twin control to prove the wiring below.
_VISIBILITY_TIMEOUT_S = 3
_DELETE_BODY = "delete-then-empty:delete-me"
_KEEP_BODY = "delete-then-empty:keep-me"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """After DeleteMessage the message never reappears, even past its visibility timeout, while an
    undeleted sibling received with it reappears on schedule as the control.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    sqs.send_message(QueueUrl=url, MessageBody=_DELETE_BODY)
    sqs.send_message(QueueUrl=url, MessageBody=_KEEP_BODY)

    received = {}
    deadline = time.monotonic() + 30.0
    while len(received) < 2 and time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=2,
            VisibilityTimeout=_VISIBILITY_TIMEOUT_S,
        )
        for msg in resp.get("Messages", []):
            received.setdefault(msg["Body"], msg)
    if len(received) < 2:
        raise AssertionError(f"expected both messages receivable, got {sorted(received)}")

    sqs.delete_message(QueueUrl=url, ReceiptHandle=received[_DELETE_BODY]["ReceiptHandle"])

    # Hold the window well past the visibility timeout: long enough for the undeleted
    # sibling to redeliver with margin, short enough to keep the check fast.
    seen = set()
    window_deadline = time.monotonic() + _VISIBILITY_TIMEOUT_S * 5
    while _KEEP_BODY not in seen and time.monotonic() < window_deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        for msg in resp.get("Messages", []):
            seen.add(msg["Body"])
        assert _DELETE_BODY not in seen, "deleted message reappeared after its visibility timeout expired"

    assert _KEEP_BODY in seen, (
        "positive control failed: the undeleted sibling never reappeared after its visibility "
        "timeout elapsed, so the absence of the deleted message is inconclusive"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
