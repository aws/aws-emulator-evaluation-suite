"""message-attribute-type-length-bounds-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "message-attribute-type-length-bounds-rejected"
GROUP = "message-attributes"
SERVICES = ["sqs"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendMessage refuses a message attribute DataType of 257 bytes with its exact message and
    enqueues nothing; a 256-byte DataType with the same valid 'String' prefix is accepted and
    round-trips unchanged.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-attrtypelen-"),
        tags={"sim2real-check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    over = "String." + "s" * 250  # 257 bytes
    assert len(over) == 257, f"the over-limit probe must be 257 bytes, got {len(over)}"
    code, message = _error(lambda: sqs.send_message(
        QueueUrl=url, MessageBody="sim2real-refused",
        MessageAttributes={"N": {"DataType": over, "StringValue": "v"}}))
    assert code == "InvalidParameterValue", f"257-byte DataType: expected InvalidParameterValue, got {code!r}"
    assert message == "Message (user) attribute type must be shorter than 256 bytes.", (
        f"257-byte DataType: unexpected message {message!r}"
    )

    at_bound = "String." + "s" * 249  # 256 bytes
    assert len(at_bound) == 256, f"the boundary probe must be 256 bytes, got {len(at_bound)}"
    sqs.send_message(QueueUrl=url, MessageBody="sim2real-accepted",
                     MessageAttributes={"N": {"DataType": at_bound, "StringValue": "v"}})

    got: dict[str, dict] = {}
    timeout_s = _budget_s(ctx, 30)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and not {"sim2real-accepted"} <= set(got):
        for msg in sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2, MessageAttributeNames=["All"]
        ).get("Messages", []):
            got[msg["Body"]] = msg.get("MessageAttributes", {}).get("N", {})
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    assert "sim2real-refused" not in got, (
        f"the refused 257-byte DataType must not have been enqueued, but it was received: "
        f"{got.get('sim2real-refused')!r}"
    )
    if "sim2real-accepted" not in got:
        raise TimeoutError(f"the accepted message was not delivered within {timeout_s:.0f}s")
    accepted = got["sim2real-accepted"]
    assert accepted and accepted.get("DataType") == at_bound, (
        f"the 256-byte DataType must round-trip unchanged, got {accepted!r}"
    )


def _error(fn) -> tuple[str, str]:
    """The (Code, Message) of the ClientError ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _budget_s(ctx, cap_s):
    """A wait's timeout, bounded by the runner's remaining time so the wait fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
