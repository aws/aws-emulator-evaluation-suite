"""receive-message-attribute-names-star-all-dot-star-select-the-same-set."""
from __future__ import annotations

import struct
import time
from hashlib import md5

from behavioral_harness import tags

CHECK = "receive-message-attribute-names-star-all-dot-star-select-the-same-set"
GROUP = "message-attributes"
SERVICES = ["sqs"]

_ATTRS = {
    "order.id": {"DataType": "String", "StringValue": "A-1"},
    "status": {"DataType": "String", "StringValue": "open"},
}


def _digest(attributes: dict) -> str:
    """The documented MD5 over an attribute map: sorted names, length-prefixed fields, one hash.

    https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-message-metadata.html
    """
    h = md5(usedforsecurity=False)  # noqa: S324 - reproducing AWS's documented digest
    for name in sorted(attributes):
        spec = attributes[name]
        name_bytes = name.encode("utf-8")
        h.update(struct.pack(">I", len(name_bytes)))
        h.update(name_bytes)
        type_bytes = spec["DataType"].encode("utf-8")
        h.update(struct.pack(">I", len(type_bytes)))
        h.update(type_bytes)
        value_bytes = spec["StringValue"].encode("utf-8")
        h.update(b"\x01")
        h.update(struct.pack(">I", len(value_bytes)))
        h.update(value_bytes)
    return h.hexdigest()


def _receive_projected(sqs, url: str, names: list[str], *, timeout_s: float) -> dict:
    """Receive the one message under ``names``, reset its visibility, and return it."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2, VisibilityTimeout=0,
            MessageAttributeNames=names,
        ).get("Messages", [])
        if msgs:
            return msgs[0]
    raise AssertionError(f"no message was receivable within {timeout_s}s for names={names!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """MessageAttributeNames=['*'] projects every attribute with the send-time MD5, the same as
    'All' and '.*'; a name prefix or an exact name projects only the matching subset, with
    MD5OfMessageAttributes recomputed over that subset rather than echoed from SendMessage."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-sqs-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    poll_s = 30.0

    full_digest = _digest(_ATTRS)
    prefix_digest = _digest({"order.id": _ATTRS["order.id"]})
    exact_digest = _digest({"status": _ATTRS["status"]})
    assert full_digest not in (prefix_digest, exact_digest), (
        "the full-set digest must differ from both single-attribute subset digests, or this "
        f"check cannot discriminate them: full={full_digest!r} prefix={prefix_digest!r} "
        f"exact={exact_digest!r}"
    )

    sent = sqs.send_message(
        QueueUrl=url, MessageBody="sim2real-attribute-projection", MessageAttributes=_ATTRS
    )
    sent_digest = sent.get("MD5OfMessageAttributes")
    assert sent_digest == full_digest, (
        f"SendMessage's MD5OfMessageAttributes {sent_digest!r} does not match the documented "
        f"canonical digest over both sent attributes {full_digest!r}"
    )

    # --- '*', 'All' and '.*' each project the whole set with the send-time digest -----------
    for names in (["*"], ["All"], [".*"]):
        msg = _receive_projected(sqs, url, names, timeout_s=poll_s)
        assert msg["MessageId"] == sent["MessageId"], (
            f"MessageAttributeNames={names!r} returned a different message: {msg['MessageId']!r}"
        )
        got = msg.get("MessageAttributes") or {}
        assert set(got) == set(_ATTRS), (
            f"MessageAttributeNames={names!r} returned {sorted(got)}, expected {sorted(_ATTRS)}"
        )
        for name, spec in _ATTRS.items():
            assert got[name]["StringValue"] == spec["StringValue"], (
                f"attribute {name!r} under {names!r} carried {got[name].get('StringValue')!r}, "
                f"expected {spec['StringValue']!r}"
            )
        got_digest = msg.get("MD5OfMessageAttributes")
        assert got_digest == full_digest == sent_digest, (
            f"MessageAttributeNames={names!r} returned digest {got_digest!r}; expected it to "
            f"equal both the recomputed full-set digest {full_digest!r} and SendMessage's own "
            f"digest {sent_digest!r}"
        )

    # --- a name prefix selects only the matching attribute, digest recomputed over it --------
    msg = _receive_projected(sqs, url, ["order.*"], timeout_s=poll_s)
    assert msg["MessageId"] == sent["MessageId"], (
        f"MessageAttributeNames=['order.*'] returned a different message: {msg['MessageId']!r}"
    )
    got = msg.get("MessageAttributes") or {}
    assert set(got) == {"order.id"}, (
        f"MessageAttributeNames=['order.*'] returned {sorted(got)}, expected ['order.id']"
    )
    assert got["order.id"]["StringValue"] == _ATTRS["order.id"]["StringValue"], (
        f"order.id carried {got['order.id'].get('StringValue')!r}, expected "
        f"{_ATTRS['order.id']['StringValue']!r}"
    )
    prefix_got_digest = msg.get("MD5OfMessageAttributes")
    assert prefix_got_digest == prefix_digest, (
        f"MessageAttributeNames=['order.*'] returned digest {prefix_got_digest!r}, expected the "
        f"digest recomputed over the one-attribute subset {prefix_digest!r}"
    )
    assert prefix_got_digest != sent_digest, (
        f"the prefix projection's digest equals SendMessage's full-set digest {sent_digest!r}; "
        "it must be recomputed over the projected subset, not echoed from SendMessage"
    )

    # --- an exact name selects only that attribute, digest recomputed over it ----------------
    msg = _receive_projected(sqs, url, ["status"], timeout_s=poll_s)
    assert msg["MessageId"] == sent["MessageId"], (
        f"MessageAttributeNames=['status'] returned a different message: {msg['MessageId']!r}"
    )
    got = msg.get("MessageAttributes") or {}
    assert set(got) == {"status"}, (
        f"MessageAttributeNames=['status'] returned {sorted(got)}, expected ['status']"
    )
    assert got["status"]["StringValue"] == _ATTRS["status"]["StringValue"], (
        f"status carried {got['status'].get('StringValue')!r}, expected "
        f"{_ATTRS['status']['StringValue']!r}"
    )
    exact_got_digest = msg.get("MD5OfMessageAttributes")
    assert exact_got_digest == exact_digest, (
        f"MessageAttributeNames=['status'] returned digest {exact_got_digest!r}, expected the "
        f"digest recomputed over the one-attribute subset {exact_digest!r}"
    )
    assert exact_got_digest != sent_digest, (
        f"the exact-name projection's digest equals SendMessage's full-set digest "
        f"{sent_digest!r}; it must be recomputed over the projected subset, not echoed from "
        "SendMessage"
    )

    sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
