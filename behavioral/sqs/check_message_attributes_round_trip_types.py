"""message-attributes-round-trip-types."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "message-attributes-round-trip-types"
GROUP = "data-plane"
SERVICES = ["sqs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """String, Number, and Binary MessageAttributes survive a SendMessage/ReceiveMessage
    round trip with their DataType and value intact."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-sqs-msgattr-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    attrs = {
        "StringAttr": {"DataType": "String", "StringValue": "hello-world"},
        "NumberAttr": {"DataType": "Number", "StringValue": "42"},
        "BinaryAttr": {"DataType": "Binary", "BinaryValue": b"\x00\x01\xff\xfe"},
    }
    sqs.send_message(QueueUrl=url, MessageBody="attrs-round-trip", MessageAttributes=attrs)

    msg = _poll_receive_one(sqs, url, timeout_s=15.0)
    assert msg["Body"] == "attrs-round-trip", f"expected body 'attrs-round-trip', got {msg['Body']!r}"
    received = msg["MessageAttributes"]

    assert received["StringAttr"]["DataType"] == "String", (
        f"expected StringAttr DataType 'String', got {received['StringAttr']['DataType']!r}"
    )
    assert received["StringAttr"]["StringValue"] == "hello-world", (
        f"expected StringAttr value 'hello-world', got {received['StringAttr']['StringValue']!r}"
    )

    assert received["NumberAttr"]["DataType"] == "Number", (
        f"expected NumberAttr DataType 'Number', got {received['NumberAttr']['DataType']!r}"
    )
    assert received["NumberAttr"]["StringValue"] == "42", (
        f"expected NumberAttr value '42', got {received['NumberAttr']['StringValue']!r}"
    )

    assert received["BinaryAttr"]["DataType"] == "Binary", (
        f"expected BinaryAttr DataType 'Binary', got {received['BinaryAttr']['DataType']!r}"
    )
    got_binary = bytes(received["BinaryAttr"]["BinaryValue"])
    assert got_binary == b"\x00\x01\xff\xfe", (
        f"expected BinaryAttr value b'\\x00\\x01\\xff\\xfe', got {got_binary!r}"
    )

    sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])


def _poll_receive_one(sqs, url, timeout_s=15.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=url,
            MaxNumberOfMessages=1,
            WaitTimeSeconds=3,
            MessageAttributeNames=["All"],
        )
        messages = resp.get("Messages", [])
        if messages:
            return messages[0]
    raise AssertionError(f"no message received within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
