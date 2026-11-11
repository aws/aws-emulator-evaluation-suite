"""change-visibility-on-expired-handle-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-visibility-on-expired-handle-rejected"
GROUP = "overly-permissive"
SERVICES = ["sqs"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ChangeMessageVisibility using a receipt handle for a message that has already been
    deleted is rejected (the handle no longer references an in-flight message), while the
    same operation on a still-in-flight message succeeds."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    message_id = sqs.send_message(QueueUrl=url, MessageBody="deleted-then-revisibilitied")[
        "MessageId"
    ]

    first = _poll_until(
        lambda: sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=5).get(
            "Messages", []
        ),
        lambda msgs: len(msgs) == 1,
        timeout_s=20.0,
    )[0]
    assert first["MessageId"] == message_id, f"expected {message_id!r}, got {first['MessageId']!r}"
    handle = first["ReceiptHandle"]

    sqs.delete_message(QueueUrl=url, ReceiptHandle=handle)

    code, message = _error(
        lambda: sqs.change_message_visibility(QueueUrl=url, ReceiptHandle=handle, VisibilityTimeout=30)
    )
    assert code == "InvalidParameterValue", (
        f"expected an error changing visibility via a deleted message's handle, got {code!r}"
    )
    expected_message = (
        f"Value {handle} for parameter ReceiptHandle is invalid. "
        "Reason: Message does not exist or is not available for visibility timeout change."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The rejected call must not resurrect the deleted message.
    for _ in range(3):
        leftover = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=1).get(
            "Messages", []
        )
        assert not any(m["MessageId"] == message_id for m in leftover), (
            f"deleted message {message_id} reappeared after rejected ChangeMessageVisibility"
        )

    sqs.send_message(QueueUrl=url, MessageBody="still-in-flight")
    second = _poll_until(
        lambda: sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=5).get(
            "Messages", []
        ),
        lambda msgs: len(msgs) == 1,
        timeout_s=20.0,
    )[0]
    sqs.change_message_visibility(QueueUrl=url, ReceiptHandle=second["ReceiptHandle"], VisibilityTimeout=30)
    sqs.change_message_visibility(QueueUrl=url, ReceiptHandle=second["ReceiptHandle"], VisibilityTimeout=0)
    cleanup_msg = _poll_until(
        lambda: sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=3).get(
            "Messages", []
        ),
        lambda msgs: len(msgs) == 1,
        timeout_s=10.0,
    )[0]
    sqs.delete_message(QueueUrl=url, ReceiptHandle=cleanup_msg["ReceiptHandle"])


def _error(fn):
    """Return (Error.Code, Error.Message) of the ClientError fn raises; raise if fn succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected the call to be refused with an error, but it succeeded")


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

