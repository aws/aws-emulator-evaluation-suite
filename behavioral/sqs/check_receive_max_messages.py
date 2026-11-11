"""receive-max-messages."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "receive-max-messages"
GROUP = 'invariants'
SERVICES = ['sqs']

_TAGS = {"sim2real-check": CHECK}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Send 5 messages: every ReceiveMessage(MaxNumberOfMessages=3) batch is capped at 3, and
    all 5 messages are eventually observed (so an empty-result stub cannot pass vacuously)."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    bodies = {f"max-msg-{i}" for i in range(5)}
    for body in bodies:
        sqs.send_message(QueueUrl=url, MessageBody=body)

    seen = {}
    idle = 0
    deadline = time.monotonic() + 30
    while len(seen) < len(bodies) and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=3, WaitTimeSeconds=2)
        batch = resp.get("Messages", [])
        if not batch:
            idle += 1
            if idle >= 3:
                break
            continue
        idle = 0
        assert len(batch) <= 3, f"expected at most 3 messages per ReceiveMessage call, got {len(batch)}"
        for m in batch:
            seen[m["MessageId"]] = m["Body"]
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])

    assert set(seen.values()) == bodies, f"expected all of {sorted(bodies)}, got {sorted(seen.values())}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
