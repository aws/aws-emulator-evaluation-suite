"""fifo-missing-message-group-id-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fifo-missing-message-group-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["sqs"]

_MISSING_GROUP_ID_MESSAGE = "The request must contain the parameter MessageGroupId."


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendMessage to a FIFO queue without the required MessageGroupId is rejected with
    MissingParameter, the message never lands on the queue, and a corrected call (same
    queue, MessageGroupId supplied) succeeds."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-sqs-fifo-noreq-") + ".fifo"
    url = sqs.create_queue(
        QueueName=name,
        Attributes={"FifoQueue": "true"},
        tags={"sim2real": "fifo-missing-message-group-id-rejected"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    error = _client_error(
        lambda: sqs.send_message(
            QueueUrl=url, MessageBody="missing-group-id", MessageDeduplicationId="d1"
        )
    )
    assert error.get("Code") == "MissingParameter", f"expected MissingParameter, got {error.get('Code')!r}"
    assert error.get("Message") == _MISSING_GROUP_ID_MESSAGE, (
        f"expected message {_MISSING_GROUP_ID_MESSAGE!r}, got {error.get('Message')!r}"
    )

    attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"])[
        "Attributes"
    ]
    assert attrs["ApproximateNumberOfMessages"] == "0", (
        f"expected 0 visible messages after the rejected send, got {attrs['ApproximateNumberOfMessages']!r}"
    )
    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
    assert not resp.get("Messages"), "message was enqueued despite the rejected SendMessage call"

    # positive control: the same call with MessageGroupId supplied succeeds end-to-end
    send_resp = sqs.send_message(
        QueueUrl=url,
        MessageBody="has-group-id",
        MessageGroupId="g1",
        MessageDeduplicationId="d2",
    )
    assert "MessageId" in send_resp, f"corrected SendMessage returned no MessageId: {send_resp!r}"

    msg = _poll_receive_one(sqs, url, timeout_s=15.0)
    assert msg["Body"] == "has-group-id", f"expected body 'has-group-id', got {msg['Body']!r}"
    sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])


def _client_error(fn):
    """The botocore Error dict, or a raise. An unexpected SUCCESS raises rather than returning a
    falsy sentinel."""
    try:
        resp = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {resp!r}")


def _poll_receive_one(sqs, url, timeout_s=15.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=3)
        messages = resp.get("Messages", [])
        if messages:
            return messages[0]
    raise AssertionError(f"no message received within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
