"""change-message-visibility-invalid-receipt-handle."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-message-visibility-invalid-receipt-handle"
GROUP = "error-semantics"
SERVICES = ["sqs"]



def _error(fn):
    """Call fn() and return (Error.Code, Error.Message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected ChangeMessageVisibility with a bogus ReceiptHandle to be REFUSED, but it "
        f"SUCCEEDED: {result!r}"
    )


def _create_queue(ctx, *, fifo=False, attributes=None):
    """Create a queue, register its teardown, and return (name, queue_url)."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sqs-check-")
    if fifo:
        name = f"{name}.fifo"
    attrs = dict(attributes or {})
    if fifo:
        attrs.setdefault("FifoQueue", "true")
    kwargs = {"QueueName": name}
    if attrs:
        kwargs["Attributes"] = attrs
    url = sqs.create_queue(**kwargs)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return name, url


def _poll_until(
    probe, predicate, *, timeout_s, interval_s=1.0, description="condition"
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not observed within {timeout_s}s; last saw {last!r}"
    )


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ChangeMessageVisibility with a bogus ReceiptHandle fails with ReceiptHandleIsInvalid and does
    not extend the real message (it reappears on its short timeout); the real handle then succeeds.
    """
    sqs = ctx.client("sqs")
    _, url = _create_queue(ctx, attributes={"VisibilityTimeout": "5"})

    sqs.send_message(QueueUrl=url, MessageBody="cmv-invalid-handle-probe")
    first = _poll_until(
        lambda: sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=5
        ).get("Messages", []),
        lambda msgs: len(msgs) == 1,
        timeout_s=20.0,
        description="initial receive of the probe message",
    )[0]

    # Break exactly one thing: a syntactically bogus receipt handle.
    code, message = _error(
        lambda: sqs.change_message_visibility(
            QueueUrl=url,
            ReceiptHandle="totally-bogus-handle",
            VisibilityTimeout=60,
        )
    )
    assert code == "ReceiptHandleIsInvalid", (
        f"expected ReceiptHandleIsInvalid, got {code!r}"
    )
    assert message == "The input receipt handle is invalid.", (
        f"expected message 'The input receipt handle is invalid.', got {message!r}"
    )

    # The queue's own 5s timeout still governs the message, so it reappears well before the
    # rejected 60s extension would have allowed.
    second = _poll_until(
        lambda: sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=5
        ).get("Messages", []),
        lambda msgs: len(msgs) == 1 and msgs[0]["MessageId"] == first["MessageId"],
        timeout_s=30.0,
        description="the probe message reappearing on its real (5s) visibility timeout",
    )[0]

    # Positive control: the same call with the message's real receipt handle succeeds.
    sqs.change_message_visibility(
        QueueUrl=url,
        ReceiptHandle=second["ReceiptHandle"],
        VisibilityTimeout=5,
    )
    sqs.delete_message(QueueUrl=url, ReceiptHandle=second["ReceiptHandle"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
