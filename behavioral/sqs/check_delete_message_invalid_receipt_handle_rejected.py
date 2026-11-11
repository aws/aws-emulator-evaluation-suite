"""delete-message-invalid-receipt-handle-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-message-invalid-receipt-handle-rejected"
GROUP = "overly-permissive"
SERVICES = ["sqs"]

_TAGS = {"sim2real:managed": "true", "sim2real": "delete-message-invalid-receipt-handle-rejected"}


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteMessage with a syntactically bogus receipt handle is rejected with
    ReceiptHandleIsInvalid; an independent read then confirms the real message was left
    untouched, and deleting it with its own (still-valid) receipt handle afterwards succeeds."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-sqs-badhandle-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    body = "protected-by-real-handle"
    message_id = sqs.send_message(QueueUrl=url, MessageBody=body)["MessageId"]
    msg = _poll_receive_one(sqs, url, timeout_s=15.0)
    assert msg["Body"] == body, f"expected body {body!r}, got {msg['Body']!r}"
    assert msg["MessageId"] == message_id, f"expected message {message_id!r}, got {msg['MessageId']!r}"

    code, message = _error(
        lambda: sqs.delete_message(QueueUrl=url, ReceiptHandle="totally-bogus-receipt-handle")
    )
    assert code == "ReceiptHandleIsInvalid", f"expected ReceiptHandleIsInvalid, got {code!r}"
    assert message == "The input receipt handle is invalid.", (
        f"expected message 'The input receipt handle is invalid.', got {message!r}"
    )

    # effect absent, by an INDEPENDENT read: force the message visible again (this is not the
    # delete under test) and receive it fresh, proving the rejected call above did not touch it.
    sqs.change_message_visibility(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"], VisibilityTimeout=0)
    still_there = _poll_until_matching(sqs, url, message_id, timeout_s=15.0)

    # positive control: the untouched message can be deleted normally with a valid receipt handle.
    sqs.delete_message(QueueUrl=url, ReceiptHandle=still_there["ReceiptHandle"])

    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        assert not resp.get("Messages"), "message reappeared after being properly deleted"


def _error(fn):
    """Return (Error.Code, Error.Message) of the ClientError fn raises; raise if fn succeeds."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected DeleteMessage to be REFUSED, but it SUCCEEDED: {result!r}")


def _poll_receive_one(sqs, url, timeout_s=15.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=3)
        messages = resp.get("Messages", [])
        if messages:
            return messages[0]
    raise AssertionError(f"no message received within {timeout_s}s")


def _poll_until_matching(sqs, url, message_id, timeout_s=15.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=3)
        for candidate in resp.get("Messages", []):
            if candidate["MessageId"] == message_id:
                return candidate
    raise AssertionError(
        f"message {message_id!r} not observed within {timeout_s}s after being made visible again"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
