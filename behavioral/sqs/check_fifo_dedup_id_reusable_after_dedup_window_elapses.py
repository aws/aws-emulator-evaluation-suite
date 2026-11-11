"""fifo-dedup-id-reusable-after-dedup-window-elapses."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "fifo-dedup-id-reusable-after-dedup-window-elapses"
GROUP = "fifo"
SERVICES = ["sqs"]

# The deduplication interval is exactly the documented 5 minutes. A send inside the window with
# the same MessageDeduplicationId is swallowed; a send issued after the window has fully elapsed
# is NOT, and mints its own new MessageId. The resend is polled every 2 s (a send inside the window
# is swallowed and never delivered) up to 330 s, a 30 s margin past the 300 s boundary.
_DEDUP_WINDOW_WAIT_S = 330.0

_TAGS = {"sim2real:managed": "true", "sim2real": "fifo-dedup-window-elapses"}


# timing:real-time — ttl: 300 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/FIFO-queues-exactly-once-processing.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A resend with the same MessageDeduplicationId is swallowed inside the 5-minute dedup window,
    but once the window has fully elapsed the same id mints a new MessageId and is delivered.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + ".fifo",
        Attributes={"FifoQueue": "true"},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    token = uuid.uuid4().hex[:8]
    group = "sim2real-group"
    dedup_id = f"{token}-window"
    body_first = f"{token}-first"
    body_second = f"{token}-second"
    body_third = f"{token}-third"

    first = sqs.send_message(
        QueueUrl=url, MessageBody=body_first, MessageGroupId=group,
        MessageDeduplicationId=dedup_id,
    )
    second = sqs.send_message(
        QueueUrl=url, MessageBody=body_second, MessageGroupId=group,
        MessageDeduplicationId=dedup_id,
    )
    assert second["MessageId"] == first["MessageId"], (
        f"positive control failed: a resend inside the dedup window minted a new MessageId "
        f"{second['MessageId']!r} instead of echoing {first['MessageId']!r}"
    )

    deadline = time.monotonic() + _DEDUP_WINDOW_WAIT_S
    if ctx.time_left() is not None:
        deadline = min(deadline, time.monotonic() + ctx.time_left() - 30.0)
    while True:
        third = sqs.send_message(
            QueueUrl=url, MessageBody=body_third, MessageGroupId=group,
            MessageDeduplicationId=dedup_id,
        )
        if third["MessageId"] != first["MessageId"] or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert third["MessageId"] != first["MessageId"], (
        f"dedup window never elapsed: sends repeated for up to {_DEDUP_WINDOW_WAIT_S}s after the "
        f"first still echoed its MessageId {first['MessageId']!r} instead of minting a new one"
    )

    bodies = []
    message_ids_seen = set()
    idle = 0
    for _ in range(15):
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
        msgs = resp.get("Messages", [])
        if not msgs:
            idle += 1
            if len(bodies) >= 2 and idle >= 3:
                break
            continue
        idle = 0
        for m in msgs:
            if m["MessageId"] in message_ids_seen:
                continue
            message_ids_seen.add(m["MessageId"])
            bodies.append(m["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])

    assert sorted(bodies) == sorted([body_first, body_third]), (
        f"expected exactly the pre-window and post-window bodies "
        f"{sorted([body_first, body_third])!r} delivered, got {sorted(bodies)!r} -- "
        f"the second (in-window) send must never have been enqueued at all"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
