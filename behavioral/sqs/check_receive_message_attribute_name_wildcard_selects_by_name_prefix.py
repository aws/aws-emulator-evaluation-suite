"""receive-message-attribute-name-wildcard-selects-by-name-prefix."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "receive-message-attribute-name-wildcard-selects-by-name-prefix"
GROUP = 'message-attributes'
SERVICES = ['sqs']

_SCENARIO = "sqs-attribute-name-wildcard"

_ATTRS = {
    "order.id": {"DataType": "String", "StringValue": "A-1"},
    "order.total": {"DataType": "Number", "StringValue": "42"},
    "orderly": {"DataType": "String", "StringValue": "yes"},
    "Order.region": {"DataType": "String", "StringValue": "west"},
    "trace": {"DataType": "Binary", "BinaryValue": b"\x01\x02"},
}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A MessageAttributeNames entry ending in ``.*`` selects by case-sensitive name prefix and
    combines with exact names; ``.*`` alone returns all, and a match of nothing omits
    MessageAttributes while the same message is still delivered with its sent values."""
    sqs = ctx.client("sqs")
    url = _create_queue(ctx)
    sent = sqs.send_message(QueueUrl=url, MessageBody="sim2real-wildcard", MessageAttributes=_ATTRS)

    def project(names: list[str]) -> tuple[str, list[str] | None]:
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2,
                                       VisibilityTimeout=0, MessageAttributeNames=names
                                       ).get("Messages", [])
            if msgs:
                attrs = msgs[0].get("MessageAttributes")
                return msgs[0]["MessageId"], None if attrs is None else sorted(attrs)
        raise AssertionError(f"the message was not receivable for selection {names!r}")

    cases = [
        (["order.*"], ["order.id", "order.total", "orderly"]),
        (["order.*", "trace"], ["order.id", "order.total", "orderly", "trace"]),
        (["Order.*"], ["Order.region"]),
        ([".*"], sorted(_ATTRS)),
        (["nothing.*"], None),
    ]
    for names, expected in cases:
        message_id, got = project(names)
        assert message_id == sent["MessageId"], (
            f"selection {names!r} received a different message than the one sent")
        assert got == expected, (
            f"MessageAttributeNames={names!r} returned attributes {got!r}, expected {expected!r}")

    _, full = project(["All"])
    values = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2,
                                 MessageAttributeNames=["order.*"]).get("Messages", [])
    assert full == sorted(_ATTRS) and values, "the message must still hold all five attributes"
    got_values = {k: v.get("StringValue") for k, v in values[0]["MessageAttributes"].items()}
    assert got_values == {"order.id": "A-1", "order.total": "42", "orderly": "yes"}, (
        f"the wildcard-selected attributes must carry their sent values, got {got_values!r}")


def _error(fn) -> tuple[str, str]:
    """The (Code, Message) of the ClientError ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_queue(ctx, attributes=None) -> str:
    """CreateQueue (tagged + prefix-named) and register DeleteQueue immediately."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-sqs-"), Attributes=attributes or {},
        tags={"sim2real": _SCENARIO, "sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda u=url: sqs.delete_queue(QueueUrl=u))
    return url


def _receive_all(ctx, url: str, wanted: set[str], timeout_s: float = 60.0, **kwargs) -> dict:
    """Receive (and delete) until every body in ``wanted`` has been seen; body -> message for
    EVERY message seen on the way."""
    sqs = ctx.client("sqs")
    seen: dict = {}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and not wanted <= set(seen):
        for msg in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2,
                                       **kwargs).get("Messages", []):
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
            seen[msg["Body"]] = msg
    missing = sorted(wanted - set(seen))
    assert not missing, (
        f"within {timeout_s}s the queue never delivered {missing!r}; it delivered {sorted(seen)!r}")
    return seen


def _receive_window(ctx, url: str, window_s: float) -> dict:
    """Receive (and delete) everything delivered within ``window_s``; body -> message."""
    sqs = ctx.client("sqs")
    seen: dict = {}
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        for msg in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                       WaitTimeSeconds=1).get("Messages", []):
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
            seen[msg["Body"]] = msg
    return seen


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
