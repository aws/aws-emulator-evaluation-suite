"""numeric-message-attribute-precision-preserved."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "numeric-message-attribute-precision-preserved"
GROUP = "invariants"
SERVICES = ["sqs"]

_TAGS = {"sim2real:managed": "true", "sim2real": "numeric-message-attribute-precision-preserved"}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Number-typed message attribute is transmitted and stored as its literal string
    value (SQS requires StringValue for Number attributes), so a high-precision decimal
    round-trips character-for-character with no floating-point truncation or rounding."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-num-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    precise_value = "3.14159265358979323846"  # 20 significant fractional digits
    sqs.send_message(
        QueueUrl=url,
        MessageBody="precision-test",
        MessageAttributes={
            "Precise": {"DataType": "Number", "StringValue": precise_value}
        },
    )

    received = _poll_for_message(ctx, url)
    attr = received["MessageAttributes"]["Precise"]
    assert attr["DataType"] == "Number", f"expected DataType Number, got {attr['DataType']!r}"
    assert attr["StringValue"] == precise_value, (
        f"precision lost: {attr['StringValue']!r} != {precise_value!r}"
    )
    sqs.delete_message(QueueUrl=url, ReceiptHandle=received["ReceiptHandle"])


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
