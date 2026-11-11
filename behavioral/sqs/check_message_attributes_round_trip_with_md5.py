"""message-attributes-round-trip-with-md5."""
from __future__ import annotations

import hashlib
import struct
import time

from behavioral_harness import tags

CHECK = "message-attributes-round-trip-with-md5"
GROUP = "invariants"
SERVICES = ["sqs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """String, Number and Binary attributes on a standard queue round-trip byte-exact, and
    MD5OfMessageAttributes on send and receive equals the documented canonical digest."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    sent = {
        "StringAttr": {"DataType": "String", "StringValue": "hello-world"},
        "NumberAttr": {"DataType": "Number", "StringValue": "42"},
        "BinaryAttr": {"DataType": "Binary", "BinaryValue": b"\x00\x01\xff\xfe"},
    }
    send_resp = sqs.send_message(QueueUrl=url, MessageBody="attrs-md5-round-trip", MessageAttributes=sent)
    sent_md5 = send_resp.get("MD5OfMessageAttributes")
    expected_md5 = _attribute_digest(sent)
    assert sent_md5 == expected_md5, (
        f"MD5OfMessageAttributes on send is {sent_md5!r}, expected the canonical digest {expected_md5!r}"
    )

    msg = _poll_receive_one(sqs, url, timeout_s=20.0)
    assert msg["Body"] == "attrs-md5-round-trip", f"body mismatch: {msg['Body']!r}"

    received = msg.get("MessageAttributes")
    if not received:
        raise AssertionError("no MessageAttributes on receive")

    assert received["StringAttr"]["DataType"] == "String", received["StringAttr"]
    assert received["StringAttr"]["StringValue"] == "hello-world", received["StringAttr"]
    assert received["NumberAttr"]["DataType"] == "Number", received["NumberAttr"]
    assert received["NumberAttr"]["StringValue"] == "42", received["NumberAttr"]
    assert received["BinaryAttr"]["DataType"] == "Binary", received["BinaryAttr"]
    assert bytes(received["BinaryAttr"]["BinaryValue"]) == b"\x00\x01\xff\xfe", received["BinaryAttr"]

    got_md5 = msg.get("MD5OfMessageAttributes")
    if got_md5 != sent_md5:
        raise AssertionError(f"MD5OfMessageAttributes did not round-trip: send {sent_md5!r} != recv {got_md5!r}")

    sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])


def _length_prefixed(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _encode_one_attribute(name: str, definition: dict) -> bytes:
    """Encode one message attribute as the SQS Developer Guide specifies."""
    buf = _length_prefixed(name.encode("utf-8")) + _length_prefixed(definition["DataType"].encode("utf-8"))
    if "StringValue" in definition:
        return buf + b"\x01" + _length_prefixed(definition["StringValue"].encode("utf-8"))
    return buf + b"\x02" + _length_prefixed(definition["BinaryValue"])


def _attribute_digest(attributes: dict) -> str:
    """The documented MD5 over a whole attribute map: sort by name, concatenate, hash once."""
    buf = b"".join(_encode_one_attribute(n, attributes[n]) for n in sorted(attributes))
    return hashlib.md5(buf).hexdigest()  # noqa: S324 - reproducing AWS's documented digest


def _poll_receive_one(sqs, url, timeout_s=20.0):
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
