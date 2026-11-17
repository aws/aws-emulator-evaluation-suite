"""wildcard-attribute-filter-subset-digest-contrasts-full-digest."""
from __future__ import annotations

import struct
import time
from hashlib import md5

from behavioral_harness import tags

CHECK = "wildcard-attribute-filter-subset-digest-contrasts-full-digest"
GROUP = "message-attributes"
SERVICES = ["sqs"]

_ATTRS = {
    "color.primary": {"DataType": "String", "StringValue": "crimson"},
    "color": {"DataType": "String", "StringValue": "red"},
    "colorful": {"DataType": "String", "StringValue": "yes"},
    "secret": {"DataType": "String", "StringValue": "do-not-project"},
}
_WILDCARD_SUBSET = {"color.primary", "color", "colorful"}


def _attribute_digest(attributes: dict) -> str:
    """The documented MD5 over a whole attribute map: sort by name, concatenate, hash once.

    https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-message-metadata.html
    """
    h = md5(usedforsecurity=False)  # noqa: S324 - reproducing AWS's documented digest
    for name in sorted(attributes):
        spec = attributes[name]
        name_bytes = name.encode("utf-8")
        h.update(struct.pack(">I", len(name_bytes)))
        h.update(name_bytes)
        data_type_bytes = spec["DataType"].encode("utf-8")
        h.update(struct.pack(">I", len(data_type_bytes)))
        h.update(data_type_bytes)
        value_bytes = spec["StringValue"].encode("utf-8")
        h.update(b"\x01")
        h.update(struct.pack(">I", len(value_bytes)))
        h.update(value_bytes)
    return h.hexdigest()


def _poll_receive(sqs, url, *, timeout_s, **kwargs) -> dict:
    """Bounded poll for a single message; raises on the deadline."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2, **kwargs
        ).get("Messages", [])
        if msgs:
            return msgs[0]
    raise AssertionError(f"no message received within {timeout_s}s for kwargs {kwargs!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A ``color.*`` projection returns exactly the three matching attributes with
    MD5OfMessageAttributes recomputed over that subset, distinct from the full-set digest; after a
    visibility reset, projecting ``All`` returns all four with the digest SendMessage reported."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-sqs-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    poll_s = 30.0

    full_digest = _attribute_digest(_ATTRS)
    subset_digest = _attribute_digest({k: _ATTRS[k] for k in _WILDCARD_SUBSET})
    assert subset_digest != full_digest, (
        "the subset and full digests must differ, or this check cannot discriminate them: both "
        f"are {full_digest!r}"
    )

    sent = sqs.send_message(QueueUrl=url, MessageBody="wildcard-digest-subject", MessageAttributes=_ATTRS)
    sent_digest = sent.get("MD5OfMessageAttributes")
    assert sent_digest == full_digest, (
        f"SendMessage's MD5OfMessageAttributes {sent_digest!r} does not match the documented "
        f"canonical digest over all four sent attributes {full_digest!r}"
    )

    # --- (a) the color.* projection: exactly the three-member subset, subset digest ----------
    msg = _poll_receive(sqs, url, timeout_s=poll_s, MessageAttributeNames=["color.*"])
    assert msg["MessageId"] == sent["MessageId"], (
        f"the color.* receive returned a different message than the one sent: {msg['MessageId']!r}"
    )
    got = msg.get("MessageAttributes") or {}
    assert set(got) == _WILDCARD_SUBSET, (
        f"MessageAttributeNames=['color.*'] returned {sorted(got)}, expected {sorted(_WILDCARD_SUBSET)}"
    )
    for name in _WILDCARD_SUBSET:
        assert got[name]["StringValue"] == _ATTRS[name]["StringValue"], (
            f"attribute {name!r} carried value {got[name].get('StringValue')!r}, expected "
            f"{_ATTRS[name]['StringValue']!r}"
        )
    subset_handle = msg["ReceiptHandle"]
    got_digest = msg.get("MD5OfMessageAttributes")
    assert got_digest == subset_digest, (
        f"the color.* projection's MD5OfMessageAttributes is {got_digest!r}, expected the digest "
        f"recomputed over just the three-member subset {subset_digest!r}"
    )
    # The strong half of the claim: a server that merely echoes SendMessage's own digest, rather
    # than recomputing it over the projected subset, must fail here.
    assert got_digest != full_digest, (
        f"the color.* projection's digest equals the full four-attribute digest {full_digest!r}; "
        "it must be recomputed over the three-member projected subset, not echoed from SendMessage"
    )

    # --- (b) reset visibility, then project All: all four, digest equal to SendMessage's ----
    sqs.change_message_visibility(QueueUrl=url, ReceiptHandle=subset_handle, VisibilityTimeout=0)
    msg_all = _poll_receive(sqs, url, timeout_s=poll_s, MessageAttributeNames=["All"])
    assert msg_all["MessageId"] == sent["MessageId"], (
        f"the All receive after the visibility reset returned a different message: "
        f"{msg_all['MessageId']!r}"
    )
    got_all = msg_all.get("MessageAttributes") or {}
    assert set(got_all) == set(_ATTRS), (
        f"MessageAttributeNames=['All'] returned {sorted(got_all)}, expected {sorted(_ATTRS)}"
    )
    for name, spec in _ATTRS.items():
        assert got_all[name]["StringValue"] == spec["StringValue"], (
            f"attribute {name!r} under All carried {got_all[name].get('StringValue')!r}, expected "
            f"{spec['StringValue']!r}"
        )
    all_digest = msg_all.get("MD5OfMessageAttributes")
    assert all_digest == full_digest == sent_digest, (
        f"the All projection's MD5OfMessageAttributes is {all_digest!r}; expected it to equal both "
        f"the recomputed full-set digest {full_digest!r} and SendMessage's own digest {sent_digest!r}"
    )

    sqs.delete_message(QueueUrl=url, ReceiptHandle=msg_all["ReceiptHandle"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
