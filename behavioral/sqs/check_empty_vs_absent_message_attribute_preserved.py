"""empty-vs-absent-message-attribute-preserved."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "empty-vs-absent-message-attribute-preserved"
GROUP = "invariants"
SERVICES = ["sqs"]

_EMPTY_VALUE_MESSAGE = "Message (user) attribute 'Coupon' must contain a non-empty value of type 'String'."

_TAGS = {"sim2real:managed": "true", "sim2real": "empty-vs-absent-message-attribute-preserved"}


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """SQS rejects an attribute with an explicit empty-string value as InvalidParameterValue; a send
    omitting the attribute receives with it absent, and a long poll after it never returns the rejected body."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-attr-"), tags=_TAGS
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    error = _client_error(
        lambda: sqs.send_message(
            QueueUrl=url,
            MessageBody="empty-attr-attempt",
            MessageAttributes={"Coupon": {"DataType": "String", "StringValue": ""}},
        )
    )
    assert error.get("Code") == "InvalidParameterValue", (
        f"expected InvalidParameterValue, got {error.get('Code')!r}"
    )
    assert error.get("Message") == _EMPTY_VALUE_MESSAGE, (
        f"expected message {_EMPTY_VALUE_MESSAGE!r}, got {error.get('Message')!r}"
    )

    # Positive control: omit the attribute entirely -> succeeds, attribute is absent on receive.
    sqs.send_message(QueueUrl=url, MessageBody="no-attr-message")
    received = _poll_for_message(ctx, url)
    assert received["Body"] == "no-attr-message", (
        f"expected body 'no-attr-message', got {received['Body']!r}"
    )
    received_attrs = received.get("MessageAttributes", {})
    assert "Coupon" not in received_attrs, (
        f"expected 'Coupon' absent (never sent), got present with "
        f"{received_attrs.get('Coupon')!r}"
    )
    sqs.delete_message(QueueUrl=url, ReceiptHandle=received["ReceiptHandle"])

    # Effect absent: the rejected send preceded the control, which is now received, so a long
    # poll (it consults every SQS server, unlike the approximate counters) would return it.
    leftover = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
    leftover_bodies = [m["Body"] for m in leftover.get("Messages", [])]
    assert "empty-attr-attempt" not in leftover_bodies, (
        f"the rejected send reached the queue: a long poll after the control returned {leftover_bodies!r}"
    )


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _poll_for_message(ctx, url, timeout_s=30.0):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=5, MessageAttributeNames=["All"]
        )
        msgs = resp.get("Messages", [])
        if msgs:
            return msgs[0]
    raise AssertionError("no message received within timeout")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
