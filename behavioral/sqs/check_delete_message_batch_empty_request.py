"""delete-message-batch-empty-request."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-message-batch-empty-request"
GROUP = 'error-semantics'
SERVICES = ['sqs']

# Empirically-confirmed SQS error codes (real AWS returns these legacy
# "AWS.SimpleQueueService.*" prefixed codes, not the bare Smithy shape names).
EMPTY_BATCH = "AWS.SimpleQueueService.EmptyBatchRequest"


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises; raise if it succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be refused with an error, but it succeeded")


def _create_queue(ctx, *, fifo=False, attributes=None):
    """Create a queue, register its teardown, and return (name, queue_url)."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sqs-check-")
    if fifo:
        name = f"{name}.fifo"
    attrs = dict(attributes or {})
    if fifo:
        attrs.setdefault("FifoQueue", "true")
    kwargs = {"QueueName": name, "tags": {"sim2real-check": CHECK}}
    if attrs:
        kwargs["Attributes"] = attrs
    url = sqs.create_queue(**kwargs)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return name, url


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteMessageBatch with a real entry succeeds (positive control); with an empty
    Entries list it fails with EmptyBatchRequest."""
    sqs = ctx.client("sqs")
    _, url = _create_queue(ctx)

    # Positive control: DeleteMessageBatch against this queue works for a real entry,
    # so the empty-Entries rejection below cannot be mistaken for "rejects everything".
    sqs.send_message(QueueUrl=url, MessageBody=ctx.unique_name("sim2real-behav-sqs-check-msg-"))
    receipt = None
    for _ in range(10):
        msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2).get("Messages", [])
        if msgs:
            receipt = msgs[0]["ReceiptHandle"]
            break
    if receipt is None:
        raise AssertionError("expected to receive the message sent for the positive control")
    positive = sqs.delete_message_batch(QueueUrl=url, Entries=[{"Id": "1", "ReceiptHandle": receipt}])
    assert not positive.get("Failed"), f"positive-control DeleteMessageBatch failed: {positive.get('Failed')}"

    code, message = _error(lambda: sqs.delete_message_batch(QueueUrl=url, Entries=[]))
    assert code == EMPTY_BATCH, f"expected {EMPTY_BATCH}, got {code}"
    expected_message = "There should be at least one DeleteMessageBatchRequestEntry in the request."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
