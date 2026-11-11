"""fifo-send-without-dedup-id-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fifo-send-without-dedup-id-fails"
GROUP = 'overly-permissive'
SERVICES = ['sqs']

_NO_DEDUP_ID_MESSAGE = (
    "The queue should either have ContentBasedDeduplication enabled or MessageDeduplicationId "
    "provided explicitly"
)


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the send to be rejected, but it SUCCEEDED: {result!r}")


def _create_queue(ctx, *, fifo=False, attributes=None):
    """Create a queue, register its teardown, and return (name, queue_url)."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sqs-check-")
    if fifo:
        name = f"{name}.fifo"
    attrs = dict(attributes or {})
    if fifo:
        attrs.setdefault("FifoQueue", "true")
    kwargs = {"QueueName": name, "tags": {"sim2real": "behavioral-check"}}
    if attrs:
        kwargs["Attributes"] = attrs
    url = sqs.create_queue(**kwargs)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return name, url


def _poll_receive_one(sqs, url, *, timeout_s=15.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=3)
        messages = resp.get("Messages", [])
        if messages:
            return messages[0]
    raise AssertionError(f"no message received within {timeout_s}s")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """FIFO send without dedup id and without ContentBasedDeduplication MUST be rejected with the
    specific error, must leave no message on the queue, and the same queue must still accept a
    correctly-formed send (dedup id supplied) end-to-end."""
    sqs = ctx.client("sqs")
    _, url = _create_queue(ctx, fifo=True)

    error = _client_error(
        lambda: sqs.send_message(QueueUrl=url, MessageBody="x", MessageGroupId="g1")
    )
    assert error.get("Code") == "InvalidParameterValue", (
        f"FIFO send lacking MessageDeduplicationId on a queue without ContentBasedDeduplication "
        f"was rejected with {error.get('Code')!r}, expected 'InvalidParameterValue'"
    )
    assert error.get("Message") == _NO_DEDUP_ID_MESSAGE, (
        f"expected message {_NO_DEDUP_ID_MESSAGE!r}, got {error.get('Message')!r}"
    )

    attrs = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]
    assert attrs["ApproximateNumberOfMessages"] == "0", (
        f"queue depth was {attrs['ApproximateNumberOfMessages']!r} after a rejected send, "
        "expected '0'"
    )
    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
    assert not resp.get("Messages"), (
        f"message(s) landed on the queue despite the rejected SendMessage call: "
        f"{resp.get('Messages')!r}"
    )

    # Positive control: the identical queue, same call shape, with MessageDeduplicationId
    # supplied, succeeds end-to-end -- this is what separates "rejects a send lacking a dedup
    # id" from "rejects every send to this queue".
    send_resp = sqs.send_message(
        QueueUrl=url, MessageBody="ok", MessageGroupId="g1", MessageDeduplicationId="d1"
    )
    assert "MessageId" in send_resp, f"corrected send did not return a MessageId: {send_resp!r}"
    msg = _poll_receive_one(sqs, url, timeout_s=15.0)
    assert msg["Body"] == "ok", f"received body {msg['Body']!r}, expected 'ok'"
    sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
