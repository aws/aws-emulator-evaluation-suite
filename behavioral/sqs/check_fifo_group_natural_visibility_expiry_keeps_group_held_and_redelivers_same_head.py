"""fifo-group-natural-visibility-expiry-keeps-group-held-and-redelivers-same-head."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "fifo-group-natural-visibility-expiry-keeps-group-held-and-redelivers-same-head"
GROUP = "fifo"
SERVICES = ["sqs"]

# The visibility timeout is left to lapse on its own; no ChangeMessageVisibility(0) handoff.
_VISIBILITY_S = 5

_TAGS = {"sim2real:managed": "true", "sim2real": "fifo-group-natural-vt-expiry"}


# timing:real-time — visibility: 5 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """An undeleted FIFO head message holds its group until its visibility timeout lapses naturally.

    The group then redelivers the SAME head (same MessageId), and the rest drain in send order.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + ".fifo",
        Attributes={"FifoQueue": "true", "VisibilityTimeout": str(_VISIBILITY_S)},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    token = uuid.uuid4().hex[:8]
    group = "sim2real-group"
    bodies = [f"{token}-{i}" for i in range(3)]
    for i, body in enumerate(bodies):
        sqs.send_message(
            QueueUrl=url, MessageBody=body, MessageGroupId=group,
            MessageDeduplicationId=f"{token}-{i}",
        )

    first = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2).get(
        "Messages", []
    )
    assert len(first) == 1 and first[0]["Body"] == bodies[0], (
        f"expected the group head {bodies[0]!r} alone, got {first!r}"
    )
    head_id = first[0]["MessageId"]

    held = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1).get(
        "Messages", []
    )
    assert held == [], (
        f"group must stay held while its head is in flight, but a second poll returned {held!r}"
    )

    # MaxNumberOfMessages=1: a larger batch could also return the head's queued successors once
    # the group reopens; one at a time isolates the head's own redelivery.
    after_expiry = []
    wait_s = _VISIBILITY_S + 30
    left = ctx.time_left()
    deadline = time.monotonic() + (wait_s if left is None else min(wait_s, left))
    while not after_expiry and time.monotonic() < deadline:
        after_expiry = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=1
        ).get("Messages", [])
        if not after_expiry:
            time.sleep(1)
    assert len(after_expiry) == 1 and after_expiry[0]["Body"] == bodies[0], (
        f"after the visibility timeout lapsed naturally, expected the SAME head {bodies[0]!r} "
        f"redelivered alone, got {after_expiry!r}"
    )
    assert after_expiry[0]["MessageId"] == head_id, (
        f"redelivery after natural expiry minted a different MessageId "
        f"{after_expiry[0]['MessageId']!r} for what must be the same message {head_id!r}"
    )

    sqs.delete_message(QueueUrl=url, ReceiptHandle=after_expiry[0]["ReceiptHandle"])
    rest = []
    seen = set()
    idle = 0
    for _ in range(10):
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
        msgs = resp.get("Messages", [])
        if not msgs:
            idle += 1
            if rest and idle >= 2:
                break
            continue
        idle = 0
        for m in msgs:
            if m["MessageId"] in seen:
                continue
            seen.add(m["MessageId"])
            rest.append(m["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    assert rest == bodies[1:], (
        f"after draining the head, expected the group's remaining order {bodies[1:]!r}, "
        f"got {rest!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
