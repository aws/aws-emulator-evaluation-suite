"""fifo-group-blocked-by-a-poison-message-resumes-after-the-dlq-move."""

from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "fifo-group-blocked-by-a-poison-message-resumes-after-the-dlq-move"
GROUP = "fifo"
SERVICES = ["sqs"]

_MAX_RECEIVE_COUNT = 1  # the poison message moves after its 1st delivery; keeps the check cheap
_MOVE_S = 30.0  # the redrive is sub-second on AWS; generous headroom
_SUCCESSOR_S = 30.0  # the head lands in the DLQ sub-second on AWS; generous headroom
_ABSENCE_MULTIPLIER = 3  # hold the blocked-window absence for >=3x the measured delivery latency

_TAGS = {
    "sim2real:managed": "true",
    "sim2real": "fifo-poison-unblocks-group",
}


def _queue_arn(sqs, url: str) -> str:
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]


def _receive(sqs, url, *, wait_s=1):
    # One at a time: one ReceiveMessage can return several messages of a FIFO group, and with
    # maxReceiveCount=1 re-exposing an extra one would redrive it to the DLQ too.
    return sqs.receive_message(
        QueueUrl=url,
        MaxNumberOfMessages=1,
        WaitTimeSeconds=wait_s,
        MessageSystemAttributeNames=["All"],
    ).get("Messages", [])


def _await_body(sqs, url, body, *, timeout_s, what):
    """Poll until `body` is delivered; return (message, latency_s), raise on the deadline.

    Other messages are re-exposed with visibility 0, since in-flight ones block their FIFO group.
    """
    start = time.monotonic()
    deadline = start + timeout_s
    while time.monotonic() < deadline:
        found, latency = None, None
        for msg in _receive(sqs, url):
            if msg["Body"] == body:
                if found is None:
                    found, latency = msg, time.monotonic() - start
                continue
            sqs.change_message_visibility(
                QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"], VisibilityTimeout=0
            )
        if found is not None:
            return found, latency
    raise AssertionError(f"{what}: {body!r} was not delivered from {url} within {timeout_s}s")


def _drive_source_until_successor(sqs, src_url, *, poison_body, successor_body, timeout_s):
    """Poll the source until the group hands out the successor; return it and poison redeliveries.

    SQS applies the redrive policy at a receive attempt, so the source must keep being polled.
    """
    deadline = time.monotonic() + timeout_s
    poison_redeliveries = 0
    while time.monotonic() < deadline:
        found = None
        for msg in _receive(sqs, src_url):
            if msg["Body"] == successor_body:
                if found is None:
                    found = msg
                continue
            assert msg["Body"] == poison_body, (
                f"the source delivered an unexpected body {msg['Body']!r}; only {poison_body!r} "
                f"and {successor_body!r} were ever sent to this queue"
            )
            poison_redeliveries += 1
            sqs.change_message_visibility(
                QueueUrl=src_url, ReceiptHandle=msg["ReceiptHandle"], VisibilityTimeout=0
            )
        if found is not None:
            return found, poison_redeliveries
    raise AssertionError(
        f"the message group never resumed: {successor_body!r} was not delivered within "
        f"{timeout_s}s of the poison head becoming over-count ({poison_redeliveries} poison "
        f"redeliveries observed). A group that stays blocked here is stalled forever"
    )


def _await_in_dlq(sqs, dlq_url, body, *, timeout_s, what):
    """Poll the DLQ until `body` arrives; raise on the deadline."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        found = None
        for msg in _receive(sqs, dlq_url):
            if msg["Body"] == body:
                if found is None:
                    found = msg
                continue
            sqs.change_message_visibility(
                QueueUrl=dlq_url, ReceiptHandle=msg["ReceiptHandle"], VisibilityTimeout=0
            )
        if found is not None:
            return found
    raise AssertionError(f"{what}: {body!r} did not reach the DLQ within {timeout_s}s")


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A FIFO group blocked by an in-flight poison head resumes at its successor once the head is
    redriven: the head reaches the FIFO DLQ with its group id, the source is left empty, and the
    over-count head is never handed back to a client.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_ReceiveMessage.html
    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-configure-dead-letter-queue-redrive.html
    """
    sqs = ctx.client("sqs")
    fifo_attrs = {"FifoQueue": "true", "ContentBasedDeduplication": "true"}

    dlq_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-dlq-") + ".fifo",
        Attributes=dict(fifo_attrs),
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))

    src_attrs = dict(fifo_attrs)
    # 60s so the poison message stays genuinely in flight for the whole blocked window below; the
    # check never waits it out -- the redelivery that triggers the move is forced with CMV(0).
    src_attrs["VisibilityTimeout"] = "60"
    src_attrs["RedrivePolicy"] = json.dumps(
        {"deadLetterTargetArn": _queue_arn(sqs, dlq_url), "maxReceiveCount": _MAX_RECEIVE_COUNT}
    )
    src_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-src-") + ".fifo",
        Attributes=src_attrs,
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=src_url))

    token = uuid.uuid4().hex[:8]
    group_id = f"grp-{token}"
    poison_body = f"poison-head-{token}"
    successor_body = f"successor-{token}"

    # Program order inside one message group IS the delivery order SQS promises.
    sqs.send_message(QueueUrl=src_url, MessageBody=poison_body, MessageGroupId=group_id)
    sqs.send_message(QueueUrl=src_url, MessageBody=successor_body, MessageGroupId=group_id)

    # The head's first-delivery latency bounds the blocked window below.
    poison, latency_s = _await_body(
        sqs, src_url, poison_body, timeout_s=40.0, what="the group head's first delivery"
    )
    assert poison["Attributes"]["ApproximateReceiveCount"] == "1", (
        f"the group head's first delivery reported ApproximateReceiveCount="
        f"{poison['Attributes']['ApproximateReceiveCount']!r}, expected '1'"
    )
    assert poison["Attributes"]["MessageGroupId"] == group_id, (
        f"the delivered head carries MessageGroupId="
        f"{poison['Attributes'].get('MessageGroupId')!r}, expected {group_id!r}"
    )
    blocked_window_s = max(_ABSENCE_MULTIPLIER * latency_s, 3.0)

    # Positive control: blocking is in effect, so a later successor delivery is due to the redrive.
    blocked_deadline = time.monotonic() + blocked_window_s
    while time.monotonic() < blocked_deadline:
        leaked = [m for m in _receive(sqs, src_url) if m["Body"] == successor_body]
        assert not leaked, (
            f"the successor {successor_body!r} was delivered while the group head "
            f"{poison_body!r} was still in flight, breaking per-group ordering. The head's own "
            f"first delivery took {latency_s:.2f}s, so the {blocked_window_s:.1f}s window is not "
            f"merely impatience"
        )

    # Force the redelivery that exceeds maxReceiveCount.
    sqs.change_message_visibility(
        QueueUrl=src_url, ReceiptHandle=poison["ReceiptHandle"], VisibilityTimeout=0
    )
    # AWS redirects the over-count head to the DLQ without ever returning it to a client.
    successor, poison_redeliveries = _drive_source_until_successor(
        sqs,
        src_url,
        poison_body=poison_body,
        successor_body=successor_body,
        timeout_s=_MOVE_S,
    )
    assert poison_redeliveries == 0, (
        f"the poison head was handed back to a ReceiveMessage caller {poison_redeliveries} time(s) "
        f"after already exceeding maxReceiveCount={_MAX_RECEIVE_COUNT}, instead of being redirected "
        f"to the DLQ at the receive attempt without ever reaching the client (the behaviour measured "
        f"on real AWS); a client-visible over-count redelivery here means the redrive did not engage "
        f"the way it should"
    )
    assert successor["Attributes"]["ApproximateReceiveCount"] == "1", (
        f"the successor's first delivery reported ApproximateReceiveCount="
        f"{successor['Attributes']['ApproximateReceiveCount']!r}, expected '1' -- a higher count "
        f"means it had already been handed out while the head was in flight"
    )
    assert successor["Attributes"]["MessageGroupId"] == group_id, (
        f"the successor carries MessageGroupId="
        f"{successor['Attributes'].get('MessageGroupId')!r}, expected {group_id!r}"
    )
    sqs.delete_message(QueueUrl=src_url, ReceiptHandle=successor["ReceiptHandle"])

    moved = _await_in_dlq(
        sqs,
        dlq_url,
        poison_body,
        timeout_s=_SUCCESSOR_S,
        what=(
            f"with maxReceiveCount={_MAX_RECEIVE_COUNT} exceeded, the poison head must arrive in "
            f"the FIFO DLQ rather than merely vanish from the source"
        ),
    )
    assert moved["Attributes"]["MessageGroupId"] == group_id, (
        f"the DLQ copy carries MessageGroupId="
        f"{moved['Attributes'].get('MessageGroupId')!r}, expected the original {group_id!r}; a "
        f"FIFO redrive must preserve the message group"
    )
    sqs.delete_message(QueueUrl=dlq_url, ReceiptHandle=moved["ReceiptHandle"])

    # A redrive moves the message; it must not remain on the source.
    residue = [m["Body"] for m in _receive(sqs, src_url, wait_s=2)]
    assert residue == [], (
        f"the source still delivers {residue!r} after the head was redriven and the successor was "
        f"consumed; a redrive MOVES the message rather than copying it"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
