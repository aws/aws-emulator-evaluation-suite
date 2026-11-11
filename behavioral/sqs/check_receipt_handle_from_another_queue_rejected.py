"""receipt-handle-from-another-queue-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "receipt-handle-from-another-queue-rejected"
GROUP = 'errors'
SERVICES = ['sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": "cross-queue-receipt-handle"}

ERR_HANDLE = "ReceiptHandleIsInvalid"


def _handle_reason(handle):
    """The exact message, attributing the refusal to the queue rather than to a malformed handle."""
    return f'The receipt handle "{handle}" is not valid for this queue.'


def _err(fn):
    """Return (Error.Code, Error.Message) for the ClientError fn raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        e = exc.response.get("Error", {})
        return e.get("Code"), e.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _receive_one(sqs, url, *, timeout_s, wait_s=2):
    """The next message off `url`, or None. Never deletes."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        batch = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=wait_s,
            AttributeNames=["All"], MessageSystemAttributeNames=["All"],
        ).get("Messages", [])
        if batch:
            return batch[0]
    return None


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A live receipt handle minted by queue A is refused by queue B with ReceiptHandleIsInvalid.
    A's message is not deleted and is redelivered; the next handle deletes it from A for real.
    """
    sqs = ctx.client("sqs")
    marker = f"xq-marker-{uuid.uuid4().hex[:8]}"

    # VisibilityTimeout=2 makes the "still there" leg a quick redelivery.
    url_a = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + "-a",
        Attributes={"VisibilityTimeout": "2"},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url_a))

    url_b = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + "-b",
        Attributes={"VisibilityTimeout": "2"},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url_b))

    sent_id = sqs.send_message(QueueUrl=url_a, MessageBody=marker)["MessageId"]
    first = _receive_one(sqs, url_a, timeout_s=60)
    assert first is not None, (
        f"the message was never delivered off queue A, so there is no live receipt handle to "
        f"present to queue B: MessageId={sent_id!r}"
    )
    assert first["MessageId"] == sent_id, (
        f"queue A delivered a different message ({first['MessageId']!r}) than the one sent "
        f"({sent_id!r}) -- the account is dirty and the legs below would be measured against the "
        f"wrong message"
    )
    handle_a = first["ReceiptHandle"]

    code, message = _err(lambda: sqs.delete_message(QueueUrl=url_b, ReceiptHandle=handle_a))
    assert code == ERR_HANDLE, (
        f"a receipt handle minted by another queue must be refused with {ERR_HANDLE!r}, got "
        f"{code!r}"
    )
    assert message == _handle_reason(handle_a), (
        f"the refusal must be attributed to the handle belonging to another QUEUE, not merely to "
        f"a malformed or expired handle: got {message!r}"
    )

    second = _receive_one(sqs, url_a, timeout_s=60)
    assert second is not None, (
        f"queue A's message did not come back after its 2s VisibilityTimeout -- the DeleteMessage "
        f"aimed at queue B deleted it from queue A"
    )
    assert second["MessageId"] == sent_id, (
        f"queue A redelivered {second['MessageId']!r} rather than the message under test "
        f"({sent_id!r})"
    )
    assert second["Body"] == marker, (
        f"queue A's redelivered body was mutated by the cross-queue call: {second['Body']!r}"
    )
    assert int(second["Attributes"]["ApproximateReceiveCount"]) == 2, (
        f"the redelivery is not the second delivery of the same message: "
        f"ApproximateReceiveCount={second['Attributes']['ApproximateReceiveCount']!r}"
    )

    # Control: a refusal here raises out of the call: the check cannot pass by refusing every DeleteMessage.
    sqs.delete_message(QueueUrl=url_a, ReceiptHandle=second["ReceiptHandle"])
    reappeared = _receive_one(sqs, url_a, timeout_s=20, wait_s=5)
    assert reappeared is None, (
        f"the message was still redelivered after being deleted from its own queue: "
        f"{reappeared.get('Body')!r}"
    )

    b_msgs = sqs.receive_message(
        QueueUrl=url_b, MaxNumberOfMessages=10, WaitTimeSeconds=2).get("Messages", [])
    assert b_msgs == [], (
        f"queue B holds messages it never received a send for: {[m['Body'] for m in b_msgs]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
