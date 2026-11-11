"""dlq-move-preserves-standard-enqueue-timestamp-and-resets-it-for-fifo."""

from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "dlq-move-preserves-standard-enqueue-timestamp-and-resets-it-for-fifo"
GROUP = "visibility_dlq"
SERVICES = ["sqs"]

_MOVE_S = 90.0  # bounded wait per arm for the asynchronous source -> DLQ move
_MAX_RECEIVE_COUNT = 1
_DLQ_RETENTION_S = "60"  # the SQS API MINIMUM for MessageRetentionPeriod; cannot be made shorter
# Hold the message untouched on the source so the DLQ's 60s retention boundary is nearly reached
# on arrival if the enqueue instant carries over. Only the DLQ has the short retention because the
# retention expiry can fire measurably earlier than its nominal boundary.
_HOLD_S = 40.0
# Long enough to see the standard copy expire, short enough to stay inside the FIFO copy's reset
# 60s boundary.
_BOUNDARY_CHECK_S = 45.0

_TAGS = {
    "sim2real:managed": "true",
    "sim2real": "dlq-enqueue-timestamp",
}


def _queue_arn(sqs, url: str) -> str:
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]


def _make_pair(ctx, sqs, *, fifo: bool):
    """Create a (source, dlq) pair of the same type, wired by a maxReceiveCount=1 RedrivePolicy.

    A FIFO queue's DLQ must itself be FIFO and vice versa.
    """
    suffix = ".fifo" if fifo else ""
    attrs = {"FifoQueue": "true", "ContentBasedDeduplication": "true"} if fifo else {}

    dlq_attrs = dict(attrs)
    # Only the DLQ carries the 60s minimum -- see _HOLD_S for why the source does not.
    dlq_attrs["MessageRetentionPeriod"] = _DLQ_RETENTION_S
    dlq_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-dlq-") + suffix,
        Attributes=dlq_attrs,
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))

    src_attrs = dict(attrs)
    # Must exceed _HOLD_S: ChangeMessageVisibility after the message has returned to visible on its
    # own fails with ReceiptHandleIsInvalid ("the receipt handle has expired").
    src_attrs["VisibilityTimeout"] = str(int(_HOLD_S) + 60)
    src_attrs["RedrivePolicy"] = json.dumps(
        {"deadLetterTargetArn": _queue_arn(sqs, dlq_url), "maxReceiveCount": _MAX_RECEIVE_COUNT}
    )
    src_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-src-") + suffix, Attributes=src_attrs, tags=_TAGS
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=src_url))
    return src_url, dlq_url


def _await_delivery(sqs, url, *, token, timeout_s, what):
    """Bounded poll until the tokened message is delivered from `url`; RAISES on the deadline.

    Non-matching messages are re-exposed with ChangeMessageVisibility(0) -- on a FIFO queue that
    also matters for progress, because an in-flight message blocks its whole message group.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for msg in sqs.receive_message(
            QueueUrl=url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=2,
            MessageSystemAttributeNames=["All"],
        ).get("Messages", []):
            if token in msg["Body"]:
                return msg
            sqs.change_message_visibility(
                QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"], VisibilityTimeout=0
            )
    raise AssertionError(f"{what}: {token!r} was not delivered from {url} within {timeout_s}s")


def _await_dlq_move(sqs, src_url, dlq_url, *, token, timeout_s, what):
    """Drive and observe the source -> DLQ move; RAISES on the deadline.

    SQS evaluates the redrive policy when a ReceiveMessage ATTEMPTS to hand the message back, so
    each iteration pokes the SOURCE (re-exposing whatever it returns) and then reads the DLQ.
    Polling the DLQ alone can wait forever on a source nobody is consuming.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for msg in sqs.receive_message(
            QueueUrl=src_url, MaxNumberOfMessages=10, WaitTimeSeconds=1
        ).get("Messages", []):
            sqs.change_message_visibility(
                QueueUrl=src_url, ReceiptHandle=msg["ReceiptHandle"], VisibilityTimeout=0
            )
        for msg in sqs.receive_message(
            QueueUrl=dlq_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=1,
            MessageSystemAttributeNames=["All"],
        ).get("Messages", []):
            if token in msg["Body"]:
                return msg
            sqs.change_message_visibility(
                QueueUrl=dlq_url, ReceiptHandle=msg["ReceiptHandle"], VisibilityTimeout=0
            )
    raise AssertionError(f"{what}: {token!r} did not reach the DLQ within {timeout_s}s")


def _sent_ms(msg, *, where: str) -> int:
    raw = msg["Attributes"]["SentTimestamp"]
    assert raw.isdigit() and len(raw) == 13, (
        f"SentTimestamp on the {where} copy must be 13-digit epoch milliseconds, got {raw!r}"
    )
    return int(raw)


def _hold_without_receiving(seconds: float) -> None:
    """A deliberate wait with no SQS interaction: elapsed time is the experimental variable.

    Any receive here would count as a delivery against maxReceiveCount=1 and move the message early.
    """
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        time.sleep(min(1.0, deadline - time.monotonic()))


def _await_retention_boundary_split(sqs, std_dlq, fifo_dlq, *, std_token, fifo_token, timeout_s):
    """Poll both DLQs together for `timeout_s`: the standard copy must expire (its retention clock
    carried over) while the FIFO copy stays receivable throughout (its clock reset).
    """
    # VisibilityTimeout=0 on the receive keeps messages visible; a follow-up ChangeMessageVisibility
    # could race the standard copy's own retention expiry.
    deadline = time.monotonic() + timeout_s
    std_found = True
    while time.monotonic() < deadline:
        std_found = False
        for msg in sqs.receive_message(
            QueueUrl=std_dlq, MaxNumberOfMessages=10, WaitTimeSeconds=1, VisibilityTimeout=0
        ).get("Messages", []):
            if std_token in msg["Body"]:
                std_found = True

        fifo_found = False
        for msg in sqs.receive_message(
            QueueUrl=fifo_dlq, MaxNumberOfMessages=10, WaitTimeSeconds=1, VisibilityTimeout=0
        ).get("Messages", []):
            if fifo_token in msg["Body"]:
                fifo_found = True
        assert fifo_found, (
            f"the FIFO DLQ copy {fifo_token!r} disappeared from {fifo_dlq} before the {timeout_s}s "
            f"check window elapsed -- it expired as though its enqueue timestamp had NOT reset"
        )
    assert not std_found, (
        f"the standard DLQ copy {std_token!r} was still receivable from {std_dlq} after "
        f"{timeout_s}s -- its enqueue timestamp did not carry over from the original send"
    )


# timing:real-time — retention: 60 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html
@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A DLQ move keeps a standard message's enqueue instant and resets a FIFO message's: the
    standard copy expires under the DLQ's 60s retention while the FIFO copy survives.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html
    """
    sqs = ctx.client("sqs")

    std_src, std_dlq = _make_pair(ctx, sqs, fifo=False)
    fifo_src, fifo_dlq = _make_pair(ctx, sqs, fifo=True)

    token = uuid.uuid4().hex[:8]
    std_body = f"std-poison-{token}"
    fifo_body = f"fifo-poison-{token}"
    group_id = f"grp-{token}"

    sqs.send_message(QueueUrl=std_src, MessageBody=std_body)
    sqs.send_message(QueueUrl=fifo_src, MessageBody=fifo_body, MessageGroupId=group_id)

    std_first = _await_delivery(
        sqs, std_src, token=token, timeout_s=30.0, what="standard source, 1st delivery"
    )
    fifo_first = _await_delivery(
        sqs, fifo_src, token=token, timeout_s=30.0, what="FIFO source, 1st delivery"
    )
    std_src_ms = _sent_ms(std_first, where="standard source")
    fifo_src_ms = _sent_ms(fifo_first, where="FIFO source")
    assert std_first["Attributes"]["ApproximateReceiveCount"] == "1", (
        f"the standard source's first delivery reported ApproximateReceiveCount="
        f"{std_first['Attributes']['ApproximateReceiveCount']!r}, expected '1'; the message had "
        f"already been delivered before this check looked at it"
    )
    assert fifo_first["Attributes"]["ApproximateReceiveCount"] == "1", (
        f"the FIFO source's first delivery reported ApproximateReceiveCount="
        f"{fifo_first['Attributes']['ApproximateReceiveCount']!r}, expected '1'"
    )

    _hold_without_receiving(_HOLD_S)

    # Force the 2nd delivery attempt on both, which exceeds maxReceiveCount=1 and triggers the move.
    sqs.change_message_visibility(
        QueueUrl=std_src, ReceiptHandle=std_first["ReceiptHandle"], VisibilityTimeout=0
    )
    sqs.change_message_visibility(
        QueueUrl=fifo_src, ReceiptHandle=fifo_first["ReceiptHandle"], VisibilityTimeout=0
    )

    std_moved = _await_dlq_move(
        sqs,
        std_src,
        std_dlq,
        token=token,
        timeout_s=_MOVE_S,
        what="standard DLQ (maxReceiveCount=1 exceeded, so the move is due)",
    )
    fifo_moved = _await_dlq_move(
        sqs,
        fifo_src,
        fifo_dlq,
        token=token,
        timeout_s=_MOVE_S,
        what="FIFO DLQ (maxReceiveCount=1 exceeded, so the move is due)",
    )
    std_dlq_ms = _sent_ms(std_moved, where="standard DLQ")
    fifo_dlq_ms = _sent_ms(fifo_moved, where="FIFO DLQ")

    assert std_moved["Body"] == std_body, (
        f"the standard DLQ copy carried {std_moved['Body']!r}, expected {std_body!r}"
    )
    assert fifo_moved["Body"] == fifo_body, (
        f"the FIFO DLQ copy carried {fifo_moved['Body']!r}, expected {fifo_body!r}"
    )

    # _await_dlq_move's receive hid each copy for the DLQ's default 30s VisibilityTimeout; release
    # them so the boundary poll does not read that as an early expiry.
    sqs.change_message_visibility(
        QueueUrl=std_dlq, ReceiptHandle=std_moved["ReceiptHandle"], VisibilityTimeout=0
    )
    sqs.change_message_visibility(
        QueueUrl=fifo_dlq, ReceiptHandle=fifo_moved["ReceiptHandle"], VisibilityTimeout=0
    )

    # SentTimestamp is the immutable original-send instant on both queue types.
    assert std_dlq_ms == std_src_ms, (
        f"a STANDARD queue's SentTimestamp must be unchanged by a DLQ move: the source copy "
        f"reported {std_src_ms} and the DLQ copy {std_dlq_ms} "
        f"(a {std_dlq_ms - std_src_ms}ms shift)"
    )
    assert fifo_dlq_ms == fifo_src_ms, (
        f"a FIFO queue's SentTimestamp is the message's immutable original-send instant and "
        f"must also be unchanged by a DLQ move: the source copy reported {fifo_src_ms} and "
        f"the DLQ copy {fifo_dlq_ms} (a {fifo_dlq_ms - fifo_src_ms}ms shift)"
    )

    # The documented enqueue-timestamp rule is observable only through retention expiry.
    _await_retention_boundary_split(
        sqs,
        std_dlq,
        fifo_dlq,
        std_token=token,
        fifo_token=token,
        timeout_s=_BOUNDARY_CHECK_S,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
