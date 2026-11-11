"""sse-kms-invalid-key-rejected."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags

CHECK = "sse-kms-invalid-key-rejected"
GROUP = "server-side"
SERVICES = ["sqs"]


# AWS appends the request id of the inner service call to this message; it is the only part
# that varies per call.
_REQUEST_ID = re.compile(r"Request ID: [0-9A-Za-z-]+")


def _stable(message):
    if message is None:
        return None
    return _REQUEST_ID.sub("Request ID: <request-id>", message)


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SetQueueAttributes accepts a nonexistent KMS alias, but the next SendMessage fails with
    KMS.NotFoundException and enqueues nothing; clearing the key restores delivery."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-badkms-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    # Positive control: the fresh, unencrypted queue delivers normally before we touch KMS at all,
    # so a later refusal can only be attributed to the bad key and not to some other queue defect.
    sqs.send_message(QueueUrl=url, MessageBody="control-before-bad-key")
    control = _poll_for_message(ctx, url)
    assert control["Body"] == "control-before-bad-key", (
        f"expected the positive control to deliver 'control-before-bad-key', got {control['Body']!r}"
    )
    sqs.delete_message(QueueUrl=url, ReceiptHandle=control["ReceiptHandle"])

    # SQS resolves the key only when it encrypts, so setting a missing alias succeeds.
    bad_alias = "alias/sim2real-definitely-does-not-exist-9f3a1c"
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"KmsMasterKeyId": bad_alias})

    code, message = _error_code(
        lambda: sqs.send_message(QueueUrl=url, MessageBody="should-not-be-delivered")
    )
    assert code == "KMS.NotFoundException", f"expected KMS.NotFoundException, got {code!r}"
    # SQS relays the KMS error text verbatim; the KMS request id is the only varying part.
    expected = (
        f"Alias arn:aws:kms:{ctx.region}:{ctx.account}:{bad_alias} is not found. (Service: AWSKMS; "
        "Status Code: 400; Error Code: NotFoundException; Request ID: <request-id>; Proxy: null)"
    )
    assert _stable(message) == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: nothing was actually enqueued.
    count = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]["ApproximateNumberOfMessages"]
    assert count == "0", f"expected 0 messages after the rejected send, saw {count!r}"

    # Positive control: clear the bad key on the same queue and delivery works again.
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"KmsMasterKeyId": ""})
    sqs.send_message(QueueUrl=url, MessageBody="delivered-after-fixing-key")
    received = _poll_for_message(ctx, url)
    assert received["Body"] == "delivered-after-fixing-key", (
        f"expected 'delivered-after-fixing-key' once the bad key is cleared, got {received['Body']!r}"
    )
    sqs.delete_message(QueueUrl=url, ReceiptHandle=received["ReceiptHandle"])


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the send to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_for_message(ctx, url, timeout_s=30.0):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        msgs = resp.get("Messages", [])
        if msgs:
            return msgs[0]
    raise AssertionError("no message received within timeout")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
