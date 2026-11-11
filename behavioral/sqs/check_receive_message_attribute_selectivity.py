"""receive-message-attribute-selectivity."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "receive-message-attribute-selectivity"
GROUP = 'invariants'
SERVICES = ['sqs']

# A well-formed X-Amzn-Trace-Id value, the only documented MessageSystemAttribute.
TRACE_HEADER = (
    "Root=1-5759e988-bd862e3fe1be46a994272793;Parent=53995c3f42cd8ad8;Sampled=1"
)

def _take(sqs, url, *, timeout_s, **kwargs):
    """Receive one message with the requested projection, then re-expose it with
    ChangeMessageVisibility(0) so the next projection is taken on the same message."""
    deadline = time.monotonic() + timeout_s
    while True:
        msgs = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=1, **kwargs
        ).get("Messages", [])
        if msgs:
            msg = msgs[0]
            sqs.change_message_visibility(
                QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"], VisibilityTimeout=0
            )
            return msg
        if time.monotonic() >= deadline:
            return None


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ReceiveMessage returns exactly the projected attributes: none by default, one when named, all
    under 'All', system attributes only via MessageSystemAttributeNames (AWSTraceHeader exact), and
    MD5OfMessageAttributes is computed over the projected subset.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    poll_s = 25

    token = uuid.uuid4().hex[:8]
    body = f"attr-projection-{token}"
    sent = sqs.send_message(
        QueueUrl=url,
        MessageBody=body,
        MessageAttributes={
            "Author": {"DataType": "String", "StringValue": f"sim2real-{token}"},
            "Version": {"DataType": "Number", "StringValue": "7"},
        },
        MessageSystemAttributes={
            "AWSTraceHeader": {"DataType": "String", "StringValue": TRACE_HEADER}
        },
    )
    # SendMessage's digest covers BOTH message attributes, i.e. everything stored. The receive
    # legs below compare against it to prove the receive-side digest tracks the PROJECTION.
    sent_md5 = sent["MD5OfMessageAttributes"]
    assert sent_md5, f"SendMessage did not return MD5OfMessageAttributes: {sorted(sent)}"

    # --- (a) default projection: no attribute content at all --------------------------
    msg = _take(sqs, url, timeout_s=poll_s)
    assert msg is not None and msg["Body"] == body, f"default receive got {msg}"
    assert not (msg.get("MessageAttributes") or {}), (
        f"MessageAttributes returned without being requested: "
        f"{sorted(msg.get('MessageAttributes') or {})}"
    )
    assert not (msg.get("Attributes") or {}), (
        f"system Attributes returned without being requested: "
        f"{sorted(msg.get('Attributes') or {})}"
    )
    # The receive-side digest is computed over the
    # PROJECTED subset, not over what the message stores, so an unprojected receive omits
    # MD5OfMessageAttributes entirely even though the message does have attributes.
    assert "MD5OfMessageAttributes" not in msg, (
        f"MD5OfMessageAttributes must be absent when no attribute was projected, got "
        f"{msg.get('MD5OfMessageAttributes')!r}"
    )

    # --- (b) one named attribute: exactly that one ------------------------------------
    msg = _take(sqs, url, timeout_s=poll_s, MessageAttributeNames=["Author"])
    assert msg is not None, "receive with MessageAttributeNames=['Author'] returned nothing"
    got = msg.get("MessageAttributes") or {}
    assert set(got) == {"Author"}, (
        f"projected ['Author'] but received {sorted(got)}"
    )
    assert got["Author"]["StringValue"] == f"sim2real-{token}", (
        f"Author value round-trip: {got['Author'].get('StringValue')!r}"
    )
    assert got["Author"]["DataType"] == "String", f"Author DataType {got['Author']['DataType']!r}"
    assert not (msg.get("Attributes") or {}), (
        f"MessageAttributeNames leaked system Attributes: {sorted(msg.get('Attributes') or {})}"
    )
    # One of two stored attributes was projected, so the digest must be over that subset and
    # therefore differ from the send-time digest over both.
    partial_md5 = msg.get("MD5OfMessageAttributes")
    assert partial_md5, "a projected attribute must come with MD5OfMessageAttributes"
    assert partial_md5 != sent_md5, (
        f"the digest for the ['Author'] subset must differ from the send-time digest over both "
        f"attributes, both were {partial_md5!r}"
    )

    # --- (c) 'All': both, with types preserved ----------------------------------------
    msg = _take(sqs, url, timeout_s=poll_s, MessageAttributeNames=["All"])
    assert msg is not None, "receive with MessageAttributeNames=['All'] returned nothing"
    got = msg.get("MessageAttributes") or {}
    assert set(got) == {"Author", "Version"}, f"'All' returned {sorted(got)}"
    assert got["Version"]["DataType"] == "Number", (
        f"Number DataType was not preserved: {got['Version']['DataType']!r}"
    )
    assert got["Version"]["StringValue"] == "7", (
        f"Number attributes travel as StringValue; got {got['Version'].get('StringValue')!r} "
        f"and keys {sorted(got['Version'])}"
    )
    assert not (msg.get("Attributes") or {}), (
        f"MessageAttributeNames=['All'] must not project system Attributes, got "
        f"{sorted(msg.get('Attributes') or {})}"
    )
    # Projecting everything reproduces the send-time digest byte-for-byte.
    assert msg.get("MD5OfMessageAttributes") == sent_md5, (
        f"'All' must reproduce the send-time attribute digest {sent_md5!r}, got "
        f"{msg.get('MD5OfMessageAttributes')!r}"
    )

    # --- (d) system attributes are a separate namespace, and AWSTraceHeader is exact --
    msg = _take(
        sqs, url, timeout_s=poll_s, MessageSystemAttributeNames=["AWSTraceHeader"]
    )
    assert msg is not None, "receive with MessageSystemAttributeNames returned nothing"
    sysattrs = msg.get("Attributes") or {}
    assert set(sysattrs) == {"AWSTraceHeader"}, (
        f"projected ['AWSTraceHeader'] but received system Attributes {sorted(sysattrs)}"
    )
    assert sysattrs["AWSTraceHeader"] == TRACE_HEADER, (
        f"AWSTraceHeader did not round-trip byte-exactly:\n  sent {TRACE_HEADER!r}\n"
        f"  got  {sysattrs['AWSTraceHeader']!r}"
    )
    assert not (msg.get("MessageAttributes") or {}), (
        f"MessageSystemAttributeNames leaked MessageAttributes: "
        f"{sorted(msg.get('MessageAttributes') or {})}"
    )
    assert "MD5OfMessageAttributes" not in msg, (
        f"a system-attribute-only projection projects no message attribute, so its digest must "
        f"be absent; got {msg.get('MD5OfMessageAttributes')!r}"
    )

    sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
