"""fifo-per-message-delay-seconds-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fifo-per-message-delay-seconds-rejected"
GROUP = "fifo"
SERVICES = ["sqs"]

_QUEUE_DELAY_S = 10
_DELAY_MESSAGE = (
    "Value 5 for parameter DelaySeconds is invalid. Reason: The request include parameter that "
    "is not valid for this queue type."
)


def _error(fn) -> dict:
    """The botocore Error dict ``fn`` raises. An unexpected success raises too, naming what came
    back: a FIFO queue that accepts a per-message delay must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A FIFO queue refuses a per-message DelaySeconds in SendMessage and refuses a whole
    SendMessageBatch with one such entry; DelaySeconds=0 is accepted, and accepted messages are
    held back by the queue-level delay and then delivered in order."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-fifodelay-") + ".fifo",
        Attributes={
            "FifoQueue": "true",
            "ContentBasedDeduplication": "true",
            "DelaySeconds": str(_QUEUE_DELAY_S),
        },
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    err = _error(
        lambda: sqs.send_message(
            QueueUrl=url, MessageBody="per-message-delay", MessageGroupId="g", DelaySeconds=5
        )
    )
    assert err.get("Code") == "InvalidParameterValue", (
        f"SendMessage DelaySeconds=5 on a FIFO queue gave code {err.get('Code')!r}"
    )
    assert err.get("Message") == _DELAY_MESSAGE, (
        f"expected message {_DELAY_MESSAGE!r}, got {err.get('Message')!r}"
    )

    err = _error(
        lambda: sqs.send_message_batch(
            QueueUrl=url,
            Entries=[
                {"Id": "plain", "MessageBody": "batch-sibling", "MessageGroupId": "g"},
                {"Id": "delayed", "MessageBody": "batch-delayed", "MessageGroupId": "g",
                 "DelaySeconds": 5},
            ],
        )
    )
    assert err.get("Code") == "InvalidParameterValue", (
        f"SendMessageBatch with one DelaySeconds=5 entry on a FIFO queue gave code "
        f"{err.get('Code')!r}; a FIFO batch is refused as a whole request"
    )
    assert err.get("Message") == _DELAY_MESSAGE, (
        f"expected message {_DELAY_MESSAGE!r}, got {err.get('Message')!r}"
    )

    # positive controls: no per-message delay, and an explicit DelaySeconds=0
    sent_at = time.monotonic()
    sqs.send_message(QueueUrl=url, MessageBody="plain", MessageGroupId="g")
    try:
        sqs.send_message(QueueUrl=url, MessageBody="zero-delay", MessageGroupId="g", DelaySeconds=0)
    except ClientError as exc:
        raise AssertionError(
            f"DelaySeconds=0 on a FIFO queue must be accepted, got {exc.response['Error']!r}"
        ) from exc

    early = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=0).get(
        "Messages", []
    )
    if time.monotonic() - sent_at < _QUEUE_DELAY_S:
        assert early == [], (
            f"messages were receivable before the queue's DelaySeconds={_QUEUE_DELAY_S} elapsed: "
            f"{[m['Body'] for m in early]!r}"
        )

    bodies: list[str] = [m["Body"] for m in early]
    for m in early:
        sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    deadline = time.monotonic() + _QUEUE_DELAY_S + 30
    while time.monotonic() < deadline and len(bodies) < 2:
        for m in sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        ).get("Messages", []):
            bodies.append(m["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    assert bodies == ["plain", "zero-delay"], (
        f"after the queue delay the FIFO group must deliver exactly the two accepted messages in "
        f"send order, and none of the refused ones; received {bodies!r}"
    )
    trailing = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get(
        "Messages", []
    )
    assert trailing == [], (
        f"a refused send was enqueued after all: {[m['Body'] for m in trailing]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
