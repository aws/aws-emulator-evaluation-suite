"""message-attribute-names-differing-only-in-case-are-distinct."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "message-attribute-names-differing-only-in-case-are-distinct"
GROUP = "message-attributes"
SERVICES = ["sqs"]

_ATTRS = {
    "Order": {"DataType": "String", "StringValue": "upper"},
    "order": {"DataType": "String", "StringValue": "lower"},
    "ORDER": {"DataType": "String", "StringValue": "allcaps"},
}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Message attribute names that differ only by case are three distinct attributes on the same
    message, each carrying its own sent value on receive, not one name overwriting another.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-attrcase-"),
        tags={"sim2real-check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    sent = sqs.send_message(QueueUrl=url, MessageBody="sim2real-case", MessageAttributes=_ATTRS)

    timeout_s = _budget_s(ctx, 30)
    deadline = time.monotonic() + timeout_s
    received = None
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2, MessageAttributeNames=["All"]
        ).get("Messages", [])
        if msgs:
            received = msgs[0]
            sqs.delete_message(QueueUrl=url, ReceiptHandle=received["ReceiptHandle"])
            break
    if received is None:
        raise TimeoutError(f"the message was not delivered within {timeout_s:.0f}s")
    assert received["MessageId"] == sent["MessageId"], "received a different message than sent"

    got = received.get("MessageAttributes", {})
    assert sorted(got) == sorted(_ATTRS), (
        f"expected all three case-variant names present as distinct attributes, got {sorted(got)!r}"
    )
    for name, attr in _ATTRS.items():
        got_value = got.get(name, {}).get("StringValue")
        assert got_value == attr["StringValue"], (
            f"attribute {name!r} came back as {got_value!r}, expected {attr['StringValue']!r} "
            f"(it must not have been overwritten by a different-case sibling)"
        )


def _budget_s(ctx, cap_s):
    """A wait's timeout, bounded by the runner's remaining time so the wait fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
