"""sse-sqs-managed-encryption-round-trips-body-byte-exact."""
from __future__ import annotations

import hashlib
import struct
import time
import uuid

from behavioral_harness import tags

CHECK = "sse-sqs-managed-encryption-round-trips-body-byte-exact"
GROUP = 'invariants'
SERVICES = ['sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": "sse-sqs-managed-roundtrip"}

# Deliberately awkward but entirely SQS-LEGAL: the allowed set is #x9 | #xA | #xD |
# #x20-#xD7FF | #xE000-#xFFFD | #x10000-#x10FFFF. Anything outside it is legitimately refused with
# InvalidMessageContents, which would be a different check. Covers 1-, 2-, 3- and 4-byte UTF-8
# sequences plus the three permitted control characters, because an implementation that
# encrypts/decrypts on a latin-1 or per-character basis corrupts exactly the multi-byte ones.
_BODY_PARTS = [
    "ascii-plain",
    "\t tab-and-newline \n and-carriage-return \r",
    "2-byte: éüñ Жи",          # Latin-1 supplement, Cyrillic
    "3-byte: 日本語 € �",         # CJK, euro sign, U+FFFD (the top of the range)
    "4-byte: \U0001f600\U0001f9ea\U0010fffd",           # astral plane, up to the #x10FFFF edge
    "boundary: ퟿ ",                          # the two ends of the excluded surrogate gap
]


def _attr_md5(attrs: dict) -> str:
    """The documented SQS message-attribute digest, computed independently of botocore.

    Per attribute in name order: length-prefixed name, data type, a transport byte, then the value.
    """
    buf = bytearray()
    for name in sorted(attrs):
        spec = attrs[name]
        for text in (name, spec["DataType"]):
            raw = text.encode("utf-8")
            buf += struct.pack(">I", len(raw)) + raw
        if "StringValue" in spec:
            raw = spec["StringValue"].encode("utf-8")
            buf += b"\x01"
        else:
            raw = spec["BinaryValue"]
            buf += b"\x02"
        buf += struct.pack(">I", len(raw)) + raw
    return hashlib.md5(bytes(buf)).hexdigest()


@tags("axis:happy-path", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """With SqsManagedSseEnabled=true a multibyte body and String/Binary attributes round-trip
    byte-exact, and MD5OfBody/attribute digests match values recomputed from the plaintext; an
    explicit SqsManagedSseEnabled=false queue reads back false and round-trips the same body.
    """
    sqs = ctx.client("sqs")
    # SqsManagedSseEnabled and the KMS key id attribute are mutually exclusive, so only the former is set.
    token = uuid.uuid4().hex[:8]
    body = f"sse-{token}|" + "|".join(_BODY_PARTS)

    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"),
        Attributes={"SqsManagedSseEnabled": "true"},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"])["Attributes"]
    assert attrs.get("SqsManagedSseEnabled") == "true", (
        f"SQS-managed SSE is not enabled on the queue, so nothing below is an encrypted round "
        f"trip: SqsManagedSseEnabled={attrs.get('SqsManagedSseEnabled')!r}"
    )
    assert "KmsMasterKeyId" not in attrs, (
        f"the queue also carries a CMK, so the encryption under test is ambiguous: "
        f"KmsMasterKeyId={attrs.get('KmsMasterKeyId')!r}"
    )

    # The contrast queue. Real SQS defaults SqsManagedSseEnabled to `true`, so an implementation
    # that hardcodes `true` satisfies the assertion above; only an explicit `false` that reads back
    # as `false` proves the attribute is honoured. It must still round-trip the same body, so a
    # correct implementation cannot pass by refusing the attribute.
    url_off = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + "-nosse",
        Attributes={"SqsManagedSseEnabled": "false"},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url_off))
    off_attrs = sqs.get_queue_attributes(QueueUrl=url_off, AttributeNames=["All"])["Attributes"]
    assert off_attrs.get("SqsManagedSseEnabled") == "false", (
        f"a queue created with SqsManagedSseEnabled=false read back "
        f"{off_attrs.get('SqsManagedSseEnabled')!r} -- the attribute is not honoured, so the "
        f"encrypted queue above proves nothing about encryption being enabled"
    )

    attr_string = "attr-" + "".join(_BODY_PARTS[2:5])
    attr_binary = bytes(range(256))
    msg_attrs = {
        "s": {"DataType": "String", "StringValue": attr_string},
        "b": {"DataType": "Binary", "BinaryValue": attr_binary},
    }

    sent = sqs.send_message(QueueUrl=url, MessageBody=body, MessageAttributes=msg_attrs)
    want_body_md5 = hashlib.md5(body.encode("utf-8")).hexdigest()
    # MD5OfMessageBody on the SEND response; MD5OfBody on the RECEIVE one. Not a typo.
    assert sent["MD5OfMessageBody"] == want_body_md5, (
        f"SendMessage's MD5OfMessageBody must be the digest of the PLAINTEXT body: got "
        f"{sent['MD5OfMessageBody']!r}, computed {want_body_md5!r}"
    )
    assert sent["MD5OfMessageAttributes"] == _attr_md5(msg_attrs), (
        f"SendMessage's MD5OfMessageAttributes does not match the digest recomputed from the "
        f"plaintext attributes: got {sent['MD5OfMessageAttributes']!r}, computed "
        f"{_attr_md5(msg_attrs)!r}"
    )

    got = None
    deadline = time.monotonic() + 60
    while got is None and time.monotonic() < deadline:
        for m in sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=5,
            MessageAttributeNames=["All"],
            AttributeNames=["All"], MessageSystemAttributeNames=["All"],
        ).get("Messages", []):
            got = m
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    assert got is not None, "the message sent to the SSE-SQS queue was never delivered"

    assert got["Body"] == body, (
        f"an SqsManagedSseEnabled queue did not round-trip the body byte-exact: received "
        f"{got['Body']!r}, sent {body!r}"
    )
    assert got["MD5OfBody"] == want_body_md5, (
        f"ReceiveMessage's MD5OfBody must be the digest of the PLAINTEXT body, not of the "
        f"ciphertext: got {got['MD5OfBody']!r}, computed {want_body_md5!r}"
    )

    want_attr_md5 = _attr_md5(msg_attrs)
    assert got["MD5OfMessageAttributes"] == want_attr_md5, (
        f"MD5OfMessageAttributes does not match the digest recomputed from the plaintext "
        f"attributes: got {got['MD5OfMessageAttributes']!r}, computed {want_attr_md5!r}"
    )
    assert got["MessageAttributes"]["s"]["StringValue"] == attr_string, (
        f"a String message attribute did not survive the encrypted round trip: "
        f"{got['MessageAttributes']['s']['StringValue']!r} != {attr_string!r}"
    )
    assert got["MessageAttributes"]["b"]["BinaryValue"] == attr_binary, (
        f"a Binary message attribute was corrupted by the encrypted round trip: "
        f"{got['MessageAttributes']['b']['BinaryValue']!r}"
    )

    # The contrast queue carries the same body with SSE off.
    off_sent = sqs.send_message(QueueUrl=url_off, MessageBody=body)
    assert off_sent["MD5OfMessageBody"] == want_body_md5, (
        f"the unencrypted queue's MD5OfMessageBody differs from the encrypted queue's for the "
        f"identical body -- the digest must not depend on encryption at all: got "
        f"{off_sent['MD5OfMessageBody']!r}, computed {want_body_md5!r}"
    )
    off_got = None
    off_deadline = time.monotonic() + 60
    while off_got is None and time.monotonic() < off_deadline:
        for m in sqs.receive_message(
            QueueUrl=url_off, MaxNumberOfMessages=1, WaitTimeSeconds=5,
        ).get("Messages", []):
            off_got = m
            sqs.delete_message(QueueUrl=url_off, ReceiptHandle=m["ReceiptHandle"])
    assert off_got is not None, "the message sent to the SSE-disabled contrast queue was never delivered"
    assert off_got["Body"] == body, (
        f"the SSE-disabled contrast queue did not round-trip the body byte-exact either, so the "
        f"byte-exactness above is not attributable to the encryption path: received "
        f"{off_got['Body']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
