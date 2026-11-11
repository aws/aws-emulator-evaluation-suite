"""message-digests-recomputed-from-the-documented-canonical-encoding."""

from __future__ import annotations

import hashlib
import struct
import time
import uuid

from behavioral_harness import tags

CHECK = "message-digests-recomputed-from-the-documented-canonical-encoding"
GROUP = "invariants"
SERVICES = ["sqs"]

# A well-formed X-Amzn-Trace-Id value; AWSTraceHeader is the only documented system attribute.
_TRACE_HEADER = "Root=1-5759e988-bd862e3fe1be46a994272793;Parent=53995c3f42cd8ad8;Sampled=1"

_TAGS = {
    "sim2real:managed": "true",
    "sim2real": "message-digests-recomputed",
}


def _length_prefixed(raw: bytes) -> bytes:
    """4-byte big-endian length, then the raw bytes -- the guide's only framing primitive."""
    return struct.pack(">I", len(raw)) + raw


def _encode_one_attribute(name: str, definition: dict) -> bytes:
    """Encode a single message attribute exactly as the SQS Developer Guide specifies."""
    buf = _length_prefixed(name.encode("utf-8"))
    buf += _length_prefixed(definition["DataType"].encode("utf-8"))
    if "StringValue" in definition:
        # Logical String AND Number both travel on the String transport type -> byte 1.
        buf += b"\x01" + _length_prefixed(definition["StringValue"].encode("utf-8"))
    elif "BinaryValue" in definition:
        buf += b"\x02" + _length_prefixed(definition["BinaryValue"])
    else:
        raise AssertionError(
            f"attribute {name!r} carries neither StringValue nor BinaryValue, so this check "
            f"cannot encode it: keys {sorted(definition)}"
        )
    return buf


def _attribute_digest(attributes: dict) -> str:
    """The documented MD5 over a whole attribute map: sort by name, concatenate, hash once."""
    buf = b"".join(_encode_one_attribute(n, attributes[n]) for n in sorted(attributes))
    return hashlib.md5(buf).hexdigest()  # noqa: S324 - reproducing AWS's documented digest


def _receive_one(sqs, url, *, token, timeout_s, **kwargs):
    """Bounded poll for the message whose body carries `token`; raises on the deadline.
    A standard queue's first receive can miss a message; others are re-exposed with visibility 0.
    """
    deadline = time.monotonic() + timeout_s
    seen: list[str] = []
    while time.monotonic() < deadline:
        for msg in sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2, **kwargs
        ).get("Messages", []):
            if token in msg["Body"]:
                return msg
            seen.append(msg["Body"])
            sqs.change_message_visibility(
                QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"], VisibilityTimeout=0
            )
    raise AssertionError(
        f"no message containing {token!r} arrived within {timeout_s}s; bodies seen: {seen!r}"
    )


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """SendMessage's body, attribute and system-attribute MD5s, and ReceiveMessage's, equal a local
    recomputation of the documented encoding; the attribute digest ignores insertion order and
    changes when one value byte changes.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-message-metadata.html
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    poll_s = 40.0

    token = uuid.uuid4().hex[:8]
    body = f"digest-subject-{token}"

    # Names chosen so that insertion order (zeta, alpha, mid) and sorted order
    # (alpha, mid, zeta) disagree, and so that leg (c) has something to prove. The custom
    # suffixes are deliberate: the guide requires them INSIDE the digest.
    attributes = {
        "zeta": {"DataType": "String.urn", "StringValue": f"urn:sim2real:{token}"},
        "alpha": {"DataType": "Number", "StringValue": "7"},
        "mid": {"DataType": "Binary.gzip", "BinaryValue": bytes(range(8))},
    }
    system_attributes = {"AWSTraceHeader": {"DataType": "String", "StringValue": _TRACE_HEADER}}

    want_body_md5 = hashlib.md5(body.encode("utf-8")).hexdigest()  # noqa: S324
    want_attr_md5 = _attribute_digest(attributes)
    want_sys_md5 = _attribute_digest(system_attributes)

    sent = sqs.send_message(
        QueueUrl=url,
        MessageBody=body,
        MessageAttributes=attributes,
        MessageSystemAttributes=system_attributes,
    )

    # --- (a) SendMessage's digests are the documented function of the payload ----------
    assert sent.get("MD5OfMessageBody") == want_body_md5, (
        f"MD5OfMessageBody is not md5(body UTF-8 bytes): expected {want_body_md5}, got "
        f"{sent.get('MD5OfMessageBody')!r} for a {len(body.encode('utf-8'))}-byte body"
    )
    assert sent.get("MD5OfMessageAttributes") == want_attr_md5, (
        f"MD5OfMessageAttributes does not match the documented canonical encoding of "
        f"{sorted(attributes)}: expected {want_attr_md5}, got "
        f"{sent.get('MD5OfMessageAttributes')!r}"
    )
    assert sent.get("MD5OfMessageSystemAttributes") == want_sys_md5, (
        f"MD5OfMessageSystemAttributes does not match the documented canonical encoding of "
        f"{sorted(system_attributes)}: expected {want_sys_md5}, got "
        f"{sent.get('MD5OfMessageSystemAttributes')!r}"
    )

    # --- (b) independent read at a different operation reproduces them ----------------
    got = _receive_one(
        sqs,
        url,
        token=token,
        timeout_s=poll_s,
        MessageAttributeNames=["All"],
        MessageSystemAttributeNames=["All"],
    )
    # "MD5OfBody" on a RECEIVED message, not "MD5OfMessageBody": the two operations name the same
    # digest differently, and only SendMessage's response carries MD5OfMessageBody.
    assert got["MD5OfBody"] == want_body_md5, (
        f"ReceiveMessage's MD5OfBody disagrees with the recomputed digest: expected "
        f"{want_body_md5}, got {got['MD5OfBody']!r}"
    )
    assert got.get("MD5OfMessageAttributes") == want_attr_md5, (
        f"ReceiveMessage's MD5OfMessageAttributes disagrees with the recomputed digest over the "
        f"full projection: expected {want_attr_md5}, got {got.get('MD5OfMessageAttributes')!r}"
    )
    received_attrs = got["MessageAttributes"]
    assert set(received_attrs) == set(attributes), (
        f"the round-tripped attribute NAMES differ: sent {sorted(attributes)}, got "
        f"{sorted(received_attrs)}"
    )
    assert received_attrs["zeta"]["DataType"] == "String.urn", (
        f"the custom DataType suffix was not preserved: got "
        f"{received_attrs['zeta']['DataType']!r}, expected 'String.urn'"
    )
    assert received_attrs["mid"]["DataType"] == "Binary.gzip", (
        f"the custom Binary DataType suffix was not preserved: got "
        f"{received_attrs['mid']['DataType']!r}, expected 'Binary.gzip'"
    )
    assert bytes(received_attrs["mid"]["BinaryValue"]) == attributes["mid"]["BinaryValue"], (
        f"the Binary attribute value did not round-trip byte-exactly: sent "
        f"{attributes['mid']['BinaryValue']!r}, got {received_attrs['mid'].get('BinaryValue')!r}"
    )
    assert received_attrs["alpha"]["StringValue"] == "7", (
        f"a Number attribute travels as StringValue '7'; got "
        f"{received_attrs['alpha'].get('StringValue')!r}"
    )
    sqs.delete_message(QueueUrl=url, ReceiptHandle=got["ReceiptHandle"])

    # --- (c) the digest is over the SORTED canonical form, not the wire order ---------
    reversed_attributes = {name: attributes[name] for name in reversed(list(attributes))}
    assert list(reversed_attributes) != list(attributes), (
        "the reversed-order probe is only meaningful if the two insertion orders differ; they "
        f"are both {list(attributes)}"
    )
    token_c = uuid.uuid4().hex[:8]
    body_c = f"digest-order-{token_c}"
    sent_c = sqs.send_message(
        QueueUrl=url, MessageBody=body_c, MessageAttributes=reversed_attributes
    )
    assert sent_c.get("MD5OfMessageAttributes") == want_attr_md5, (
        f"MD5OfMessageAttributes changed when the identical attribute map was sent in reversed "
        f"insertion order {list(reversed_attributes)}: expected the sorted-canonical digest "
        f"{want_attr_md5}, got {sent_c.get('MD5OfMessageAttributes')!r}"
    )

    # --- (d) sensitivity: one byte of one value, same names/types/lengths -------------
    perturbed = {name: dict(defn) for name, defn in attributes.items()}
    perturbed["mid"]["BinaryValue"] = bytes([0xFF]) + attributes["mid"]["BinaryValue"][1:]
    assert len(perturbed["mid"]["BinaryValue"]) == len(attributes["mid"]["BinaryValue"]), (
        "the perturbation must preserve the value LENGTH, otherwise a length-only digest would "
        "also change and the leg proves nothing"
    )
    want_perturbed_md5 = _attribute_digest(perturbed)
    assert want_perturbed_md5 != want_attr_md5, (
        "the local recomputation is insensitive to a one-byte value change, so this leg cannot "
        f"discriminate: both digests are {want_attr_md5}"
    )
    token_d = uuid.uuid4().hex[:8]
    body_d = f"digest-sensitivity-{token_d}"
    sent_d = sqs.send_message(QueueUrl=url, MessageBody=body_d, MessageAttributes=perturbed)
    assert sent_d.get("MD5OfMessageAttributes") == want_perturbed_md5, (
        f"flipping one byte of one Binary value must yield the recomputed digest "
        f"{want_perturbed_md5} (it was {want_attr_md5} before the flip); got "
        f"{sent_d.get('MD5OfMessageAttributes')!r}"
    )

    # Terminal read: the two extra messages are drained through a different operation than the
    # SendMessage that created them, and their digests are re-read at the destination.
    for want_token, want_md5 in ((token_c, want_attr_md5), (token_d, want_perturbed_md5)):
        msg = _receive_one(
            sqs, url, token=want_token, timeout_s=poll_s, MessageAttributeNames=["All"]
        )
        assert msg.get("MD5OfMessageAttributes") == want_md5, (
            f"the receive-side attribute digest for {want_token} was "
            f"{msg.get('MD5OfMessageAttributes')!r}, expected the recomputed {want_md5}"
        )
        sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
