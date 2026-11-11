"""fifo-group-held-for-the-extended-visibility-timeout-not-the-original."""
from __future__ import annotations

import uuid
import time

from behavioral_harness import tags

CHECK = "fifo-group-held-for-the-extended-visibility-timeout-not-the-original"
GROUP = "fifo"
SERVICES = ["sqs"]

_INITIAL_VISIBILITY_S = 4
_EXTENDED_VISIBILITY_S = 10

_TAGS = {"sim2real:managed": "true", "sim2real": "fifo-group-held-extended-vt"}


# timing:real-time — visibility: 10 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """ChangeMessageVisibility on an in-flight FIFO head message re-arms the group lock: the group
    stays held past the original timeout and opens, returning the same head, only after the extended
    one.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + ".fifo",
        Attributes={"FifoQueue": "true", "VisibilityTimeout": str(_INITIAL_VISIBILITY_S)},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    token = uuid.uuid4().hex[:8]
    group = "sim2real-group"
    bodies = [f"{token}-{i}" for i in range(2)]
    for i, body in enumerate(bodies):
        sqs.send_message(
            QueueUrl=url, MessageBody=body, MessageGroupId=group,
            MessageDeduplicationId=f"{token}-{i}",
        )

    head = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2)["Messages"][0]
    assert head["Body"] == bodies[0], f"expected the group head {bodies[0]!r}, got {head['Body']!r}"

    sqs.change_message_visibility(
        QueueUrl=url, ReceiptHandle=head["ReceiptHandle"], VisibilityTimeout=_EXTENDED_VISIBILITY_S
    )

    # Past the ORIGINAL timeout, but still inside the EXTENDED one: the group must stay held.
    time.sleep(_INITIAL_VISIBILITY_S + 2)
    still_held = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1).get(
        "Messages", []
    )
    assert still_held == [], (
        f"group released after the ORIGINAL {_INITIAL_VISIBILITY_S}s timeout despite the "
        f"extension to {_EXTENDED_VISIBILITY_S}s: got {still_held!r}"
    )

    # Past the EXTENDED timeout now: the group must release, and give back the SAME head.
    # MaxNumberOfMessages=1: a larger batch can return several already-queued members of one
    # FIFO group in a single call once the group reopens, which would not isolate the head's
    # own redelivery from its successor's first delivery.
    released = []
    wait_s = _EXTENDED_VISIBILITY_S + 30
    left = ctx.time_left()
    deadline = time.monotonic() + (wait_s if left is None else min(wait_s, left))
    while not released and time.monotonic() < deadline:
        released = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=1).get(
            "Messages", []
        )
        if not released:
            time.sleep(1)
    assert len(released) == 1 and released[0]["Body"] == bodies[0], (
        f"expected the same head {bodies[0]!r} redelivered once the extended timeout elapsed, "
        f"got {released!r}"
    )
    assert released[0]["MessageId"] == head["MessageId"], (
        f"redelivery after the extended timeout minted a different MessageId "
        f"{released[0]['MessageId']!r} for what must be the same message {head['MessageId']!r}"
    )

    sqs.delete_message(QueueUrl=url, ReceiptHandle=released[0]["ReceiptHandle"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
