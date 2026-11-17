"""fifo-message-attribute-digest-sensitivity-across-types."""
from __future__ import annotations

import hashlib
import time
import uuid

from behavioral_harness import tags

CHECK = "fifo-message-attribute-digest-sensitivity-across-types"
GROUP = "fifo"
SERVICES = ["sqs"]


def _length_prefixed(raw: bytes) -> bytes:
    return len(raw).to_bytes(4, "big") + raw


def _encode_attribute(name: str, attr: dict) -> bytes:
    buf = _length_prefixed(name.encode("utf-8"))
    buf += _length_prefixed(attr["DataType"].encode("utf-8"))
    if "BinaryValue" in attr:
        buf += b"\x02" + _length_prefixed(attr["BinaryValue"])
    else:
        buf += b"\x01" + _length_prefixed(attr["StringValue"].encode("utf-8"))
    return buf


def _attributes_digest(attrs: dict) -> str:
    """The documented per-attribute, name-sorted MD5 over DataType and value."""
    buf = b"".join(_encode_attribute(name, attrs[name]) for name in sorted(attrs))
    return hashlib.md5(buf, usedforsecurity=False).hexdigest()


def _receive_by_token(sqs, url: str, tokens: set, *, budget_s: float) -> dict:
    """Bounded poll collecting one FIFO message per body token in `tokens`."""
    deadline = time.monotonic() + budget_s
    found: dict[str, dict] = {}
    while time.monotonic() < deadline and len(found) < len(tokens):
        resp = sqs.receive_message(
            QueueUrl=url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=2,
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            matched = next((t for t in tokens if t in msg["Body"]), None)
            if matched is not None and matched not in found:
                found[matched] = msg
            elif matched is None:
                sqs.change_message_visibility(
                    QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"], VisibilityTimeout=0
                )
    missing = tokens - set(found)
    if missing:
        raise AssertionError(f"no message carrying token(s) {sorted(missing)} arrived within {budget_s}s")
    return found


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """On a FIFO queue, SendMessage with an explicit MessageDeduplicationId and String, Number,
    Binary and custom-typed attributes returns digests matching a local recomputation, which
    ReceiveMessage reproduces byte-exact; flipping one Binary byte changes the digest to match."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + ".fifo",
        Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "false"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    token_1 = uuid.uuid4().hex[:8]
    body_1 = f"fifo-digest-{token_1}"
    binary_value_1 = bytes([0x10, 0x20, 0x30, 0x40, 0x50])
    attrs_1 = {
        "str-attr": {"DataType": "String", "StringValue": f"plain-{token_1}"},
        "num-attr": {"DataType": "Number", "StringValue": "123456"},
        "bin-attr": {"DataType": "Binary", "BinaryValue": binary_value_1},
        "custom-attr": {"DataType": "String.custom", "StringValue": f"custom-{token_1}"},
    }
    want_md5_1 = _attributes_digest(attrs_1)
    want_body_md5_1 = hashlib.md5(body_1.encode("utf-8"), usedforsecurity=False).hexdigest()

    sent_1 = sqs.send_message(
        QueueUrl=url,
        MessageBody=body_1,
        MessageGroupId="g1",
        MessageDeduplicationId=f"dedup-{token_1}",
        MessageAttributes=attrs_1,
    )
    assert sent_1.get("MD5OfMessageBody") == want_body_md5_1, (
        f"MD5OfMessageBody on the first FIFO send was {sent_1.get('MD5OfMessageBody')!r}, "
        f"expected md5(body) {want_body_md5_1!r}"
    )
    assert sent_1.get("MD5OfMessageAttributes") == want_md5_1, (
        f"MD5OfMessageAttributes on the first FIFO send was {sent_1.get('MD5OfMessageAttributes')!r}, "
        f"expected the recomputed digest {want_md5_1!r}"
    )

    # Second send: a new MessageDeduplicationId (so it is not treated as a replay of the first),
    # with one byte of the Binary value flipped and every other attribute unchanged.
    token_2 = uuid.uuid4().hex[:8]
    body_2 = f"fifo-digest-{token_2}"
    binary_value_2 = bytes([0xFF]) + binary_value_1[1:]
    assert len(binary_value_2) == len(binary_value_1), (
        "the perturbation must preserve the value length so this leg proves byte sensitivity, "
        "not a length change"
    )
    attrs_2 = dict(attrs_1)
    attrs_2["bin-attr"] = {"DataType": "Binary", "BinaryValue": binary_value_2}
    want_md5_2 = _attributes_digest(attrs_2)
    assert want_md5_2 != want_md5_1, (
        "the local recomputation is insensitive to a one-byte Binary value change, so this leg "
        f"cannot discriminate: both digests are {want_md5_1!r}"
    )
    want_body_md5_2 = hashlib.md5(body_2.encode("utf-8"), usedforsecurity=False).hexdigest()

    sent_2 = sqs.send_message(
        QueueUrl=url,
        MessageBody=body_2,
        MessageGroupId="g1",
        MessageDeduplicationId=f"dedup-{token_2}",
        MessageAttributes=attrs_2,
    )
    assert sent_2.get("MD5OfMessageBody") == want_body_md5_2, (
        f"MD5OfMessageBody on the second FIFO send was {sent_2.get('MD5OfMessageBody')!r}, "
        f"expected md5(body) {want_body_md5_2!r}"
    )
    assert sent_2.get("MD5OfMessageAttributes") == want_md5_2, (
        f"MD5OfMessageAttributes after flipping one Binary byte was "
        f"{sent_2.get('MD5OfMessageAttributes')!r}, expected the newly recomputed digest "
        f"{want_md5_2!r} (it was {want_md5_1!r} before the flip)"
    )

    # Independent read: both messages, through a different operation than SendMessage.
    received = _receive_by_token(sqs, url, {token_1, token_2}, budget_s=40.0)

    msg_1 = received[token_1]
    assert msg_1["Body"] == body_1, f"delivered body {msg_1['Body']!r} != sent {body_1!r}"
    assert msg_1.get("MD5OfBody") == want_body_md5_1, (
        f"ReceiveMessage's MD5OfBody for the first message was {msg_1.get('MD5OfBody')!r}, "
        f"expected {want_body_md5_1!r}"
    )
    assert msg_1.get("MD5OfMessageAttributes") == want_md5_1, (
        f"ReceiveMessage's MD5OfMessageAttributes for the first message was "
        f"{msg_1.get('MD5OfMessageAttributes')!r}, expected the recomputed digest {want_md5_1!r}"
    )
    got_1 = msg_1.get("MessageAttributes", {})
    assert set(got_1) == set(attrs_1), f"received attribute names {sorted(got_1)} != sent {sorted(attrs_1)}"
    assert got_1["str-attr"]["DataType"] == "String", f"String attribute DataType was {got_1['str-attr']['DataType']!r}"
    assert got_1["str-attr"]["StringValue"] == attrs_1["str-attr"]["StringValue"], (
        f"String attribute value {got_1['str-attr']['StringValue']!r} != sent "
        f"{attrs_1['str-attr']['StringValue']!r}"
    )
    assert got_1["num-attr"]["DataType"] == "Number", f"Number attribute DataType was {got_1['num-attr']['DataType']!r}"
    assert got_1["num-attr"]["StringValue"] == "123456", (
        f"Number attribute value {got_1['num-attr']['StringValue']!r} != sent '123456'"
    )
    assert got_1["bin-attr"]["DataType"] == "Binary", f"Binary attribute DataType was {got_1['bin-attr']['DataType']!r}"
    assert bytes(got_1["bin-attr"]["BinaryValue"]) == binary_value_1, (
        f"Binary attribute value {bytes(got_1['bin-attr']['BinaryValue'])!r} != sent {binary_value_1!r}"
    )
    assert got_1["custom-attr"]["DataType"] == "String.custom", (
        f"custom attribute DataType {got_1['custom-attr']['DataType']!r} != sent 'String.custom'"
    )
    assert got_1["custom-attr"]["StringValue"] == attrs_1["custom-attr"]["StringValue"], (
        f"custom attribute value {got_1['custom-attr']['StringValue']!r} != sent "
        f"{attrs_1['custom-attr']['StringValue']!r}"
    )
    sqs.delete_message(QueueUrl=url, ReceiptHandle=msg_1["ReceiptHandle"])

    msg_2 = received[token_2]
    assert msg_2["Body"] == body_2, f"delivered body {msg_2['Body']!r} != sent {body_2!r}"
    assert msg_2.get("MD5OfMessageAttributes") == want_md5_2, (
        f"ReceiveMessage's MD5OfMessageAttributes for the second message was "
        f"{msg_2.get('MD5OfMessageAttributes')!r}, expected the recomputed digest {want_md5_2!r}"
    )
    got_2_bin = msg_2.get("MessageAttributes", {}).get("bin-attr", {})
    assert got_2_bin.get("DataType") == "Binary", f"Binary attribute DataType was {got_2_bin.get('DataType')!r}"
    assert bytes(got_2_bin.get("BinaryValue", b"")) == binary_value_2, (
        f"Binary attribute value {bytes(got_2_bin.get('BinaryValue', b''))!r} != the perturbed "
        f"{binary_value_2!r}"
    )
    sqs.delete_message(QueueUrl=url, ReceiptHandle=msg_2["ReceiptHandle"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
