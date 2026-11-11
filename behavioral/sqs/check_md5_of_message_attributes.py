"""md5-of-message-attributes."""
from __future__ import annotations

import struct
from hashlib import md5

from behavioral_harness import tags

CHECK = "md5-of-message-attributes"
GROUP = 'invariants'
SERVICES = ['sqs']


def _expected_md5_of_message_attributes(attrs: dict) -> str:
    """SQS's documented digest: per attribute sorted by name, length-prefixed name and data type,
    a transport byte (1 = string/number, 2 = binary), then the length-prefixed value.
    Lengths are 4-byte big-endian; text is UTF-8."""
    h = md5()
    for name in sorted(attrs):
        spec = attrs[name]
        name_bytes = name.encode("utf-8")
        h.update(struct.pack(">I", len(name_bytes)))
        h.update(name_bytes)
        data_type = spec["DataType"]
        type_bytes = data_type.encode("utf-8")
        h.update(struct.pack(">I", len(type_bytes)))
        h.update(type_bytes)
        if data_type.startswith("Binary"):
            value_bytes = spec["BinaryValue"]
            h.update(b"\x02")
        else:
            value_bytes = spec["StringValue"].encode("utf-8")
            h.update(b"\x01")
        h.update(struct.pack(">I", len(value_bytes)))
        h.update(value_bytes)
    return h.hexdigest()


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendMessage's MD5OfMessageAttributes equals a locally recomputed digest of SQS's documented
    attribute encoding, and the received message carries the same value."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    attrs = {
        "flavour": {"DataType": "String", "StringValue": "vanilla"},
        "priority": {"DataType": "Number", "StringValue": "7"},
    }
    expected_md5 = _expected_md5_of_message_attributes(attrs)
    resp = sqs.send_message(QueueUrl=url, MessageBody="md5-attrs", MessageAttributes=attrs)
    sent_md5 = resp.get("MD5OfMessageAttributes")
    assert sent_md5 == expected_md5, (
        f"MD5OfMessageAttributes on send: expected {expected_md5!r} (SQS's own digest "
        f"algorithm over {attrs!r}), got {sent_md5!r}"
    )
    received = []
    _seen = set()
    _idle = 0
    for _ in range(12):
        _resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=1, MessageAttributeNames=["All"])
        _msgs = _resp.get("Messages", [])
        if not _msgs:
            _idle += 1
            if received and _idle >= 3:
                break
            continue
        _idle = 0
        for _m in _msgs:
            if _m["MessageId"] not in _seen:
                _seen.add(_m["MessageId"])
                received.append(_m)
            sqs.delete_message(QueueUrl=url, ReceiptHandle=_m["ReceiptHandle"])
        if len(received) >= 1:
            break
    assert received, "expected at least 1 message from receive_message, got none"
    got_md5 = received[0].get("MD5OfMessageAttributes")
    assert got_md5 == expected_md5, (
        f"MD5OfMessageAttributes on receive: expected {expected_md5!r} (send returned "
        f"{sent_md5!r}), got {got_md5!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
