"""purge-queue-resets-the-fifo-dedup-cache."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "purge-queue-resets-the-fifo-dedup-cache"
GROUP = "fifo"
SERVICES = ["sqs"]

#: PurgeQueue "can take up to 60 seconds" (SQS API Reference, PurgeQueue).
PURGE_WINDOW_S = 60.0
#: Receives poll up to this long for the post-purge message.
_DRAIN_TIMEOUT_S = 30.0

_TAGS = {"sim2real:managed": "true", "sim2real": "purge-queue-resets-the-fifo-dedup-cache"}


def _drain_through(ctx, sqs, url, last_id, *, timeout_s):
    """Every (MessageId, Body) received, deleting each, up to and including ``last_id``; one FIFO
    group delivers in send order, so nothing sent before ``last_id`` can arrive after it."""
    seen = []
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get("Messages", [])
        for m in msgs:
            seen.append((m["MessageId"], m["Body"]))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
        if any(mid == last_id for mid, _ in seen):
            break
    return seen


# timing:real-time — cooldown: 60 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_PurgeQueue.html
@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A FIFO content-dedup resend before PurgeQueue reuses the first MessageId, but one right after
    PurgeQueue gets a new id; once the purge's 60 seconds pass, a resend of another pre-purge body
    gets a new id too and is delivered while neither pre-purge message ever is.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + ".fifo",
        Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true"},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    group = "g"
    body = ctx.unique_name("sim2real-behav-dedup-body-")
    late_body = ctx.unique_name("sim2real-behav-dedup-late-body-")

    first_id = sqs.send_message(QueueUrl=url, MessageBody=body, MessageGroupId=group)["MessageId"]
    late_first_id = sqs.send_message(QueueUrl=url, MessageBody=late_body, MessageGroupId=group)["MessageId"]

    # Baseline, no purge yet: the dedup cache is live and collapses an identical resend.
    baseline_repeat_id = sqs.send_message(QueueUrl=url, MessageBody=body, MessageGroupId=group)["MessageId"]
    assert baseline_repeat_id == first_id, (
        f"baseline: resending the same body with no purge in between got a NEW MessageId "
        f"{baseline_repeat_id!r}, expected the deduplicated id {first_id!r} -- dedup is not "
        f"behaving as documented in this environment, so the purge comparison below proves nothing"
    )

    purge_start = time.monotonic()
    sqs.purge_queue(QueueUrl=url)

    # The claim is specifically that this resolves BEFORE the (up to 60s) async drain completes.
    post_purge_id = sqs.send_message(QueueUrl=url, MessageBody=body, MessageGroupId=group)["MessageId"]
    assert post_purge_id != first_id, (
        f"resending the same body immediately after PurgeQueue returned a MessageId equal to the "
        f"pre-purge send ({first_id!r}) -- PurgeQueue must reset the dedup cache, not just drain "
        f"the messages"
    )

    # A message sent while the purge runs may still be deleted by it, so delivery is read off a
    # resend made once the purge's 60 seconds have passed, inside the 5-minute dedup interval of
    # its pre-purge copy.
    purge_end = purge_start + PURGE_WINDOW_S
    while time.monotonic() < purge_end:
        time.sleep(min(5.0, purge_end - time.monotonic()))
    late_id = sqs.send_message(QueueUrl=url, MessageBody=late_body, MessageGroupId=group)["MessageId"]
    assert late_id != late_first_id, (
        f"resending a pre-purge body once the purge completed returned its pre-purge MessageId "
        f"{late_first_id!r} -- PurgeQueue must reset the dedup cache"
    )

    # Effect-absent + effect-present, read back: neither pre-purge id reappears, and the resend the
    # reset let through does, with the right body. Same group, so a pre-purge message could only
    # arrive before it.
    delivered = _drain_through(ctx, sqs, url, late_id, timeout_s=_DRAIN_TIMEOUT_S)
    delivered_ids = {mid for mid, _ in delivered}
    assert first_id not in delivered_ids and late_first_id not in delivered_ids, (
        f"a pre-purge message ({first_id!r} or {late_first_id!r}) was delivered after PurgeQueue: "
        f"{delivered!r}"
    )
    assert late_id in delivered_ids, (
        f"the post-purge, non-deduplicated message {late_id!r} was never delivered: {delivered!r}"
    )
    late_bodies = [b for mid, b in delivered if mid == late_id]
    assert late_bodies == [late_body], (
        f"the post-purge message carried body {late_bodies!r}, expected {[late_body]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
