"""bad-receipt-handle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bad-receipt-handle"
GROUP = 'errors'
SERVICES = ['sqs']

ERR_BAD_RECEIPT_HANDLE = "ReceiptHandleIsInvalid"
_TAGS = {"sim2real:managed": "true", "sim2real": "bad-receipt-handle"}


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """delete_message with a syntactically bogus handle -> ReceiptHandleIsInvalid, and
    the real message's own handle -- proven live by a positive control -- still
    deletes it for real afterwards."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    body = "sim2real-bad-receipt-handle-marker"
    sent_id = sqs.send_message(QueueUrl=url, MessageBody=body)["MessageId"]
    received = _poll_receive_one(sqs, url, timeout_s=30.0)
    assert received["MessageId"] == sent_id, (
        f"queue delivered a different message ({received['MessageId']!r}) than the one "
        f"sent ({sent_id!r}) -- the account is dirty and the legs below would be measured "
        f"against the wrong message"
    )

    try:
        sqs.delete_message(QueueUrl=url, ReceiptHandle="sim2real-bogus")
        code = None
    except ClientError as exc:
        code = (exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message"))
    assert code == (ERR_BAD_RECEIPT_HANDLE, "The input receipt handle is invalid."), (
        f"expected {ERR_BAD_RECEIPT_HANDLE}, got {code!r} "
        f"(None means the operation silently succeeded instead of raising)"
    )

    # positive control: the SAME message's genuine, still-live handle deletes it for
    # real -- proving the rejection above was specific to the bogus handle rather than
    # every DeleteMessage call being refused (and, since the delete succeeds, that the
    # rejected call left the message and its handle untouched).
    sqs.delete_message(QueueUrl=url, ReceiptHandle=received["ReceiptHandle"])

    # terminal read: independent of both the send and the deletes, at the destination.
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        assert not resp.get("Messages"), "message reappeared after being properly deleted"


def _poll_receive_one(sqs, url, timeout_s=30.0):
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
