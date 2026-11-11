"""fifo-content-based-dedup-ignores-attributes."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "fifo-content-based-dedup-ignores-attributes"
GROUP = 'fifo'
SERVICES = ['sqs']



def _receive_all(sqs, url, *, expect, timeout_s, names=("All",)):
    """Receive up to `expect` distinct messages within timeout_s, preserving arrival order."""
    seen, msgs = set(), []
    deadline = time.monotonic() + timeout_s
    while len(msgs) < expect and time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=1,
            MessageAttributeNames=list(names),
        )
        for msg in resp.get("Messages", []):
            if msg["MessageId"] not in seen:
                seen.add(msg["MessageId"])
                msgs.append(msg)
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return msgs


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Content-based FIFO dedup hashes the body only: resending the same body with different
    MessageAttributes is deduplicated and the first send's attributes are retained (first write
    wins), while a different body is not deduplicated.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + ".fifo",
        Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    token = uuid.uuid4().hex[:8]
    group = f"grp-{token}"
    body = f"dedup-body-{token}"

    first = sqs.send_message(
        QueueUrl=url,
        MessageBody=body,
        MessageGroupId=group,
        MessageAttributes={"Attempt": {"DataType": "String", "StringValue": "one"}},
    )
    second = sqs.send_message(
        QueueUrl=url,
        MessageBody=body,
        MessageGroupId=group,
        # Break exactly one thing relative to the first send: the attributes, not the body.
        MessageAttributes={
            "Attempt": {"DataType": "String", "StringValue": "two"},
            "Extra": {"DataType": "Number", "StringValue": "42"},
        },
    )

    # The two requests genuinely differed -- otherwise this check proves nothing.
    md5_1 = first.get("MD5OfMessageAttributes")
    md5_2 = second.get("MD5OfMessageAttributes")
    assert md5_1 and md5_2, (
        f"SendMessage did not echo MD5OfMessageAttributes ({md5_1!r}, {md5_2!r}); "
        "cannot establish that the two requests differed"
    )
    assert md5_1 != md5_2, (
        f"both sends hashed their attributes to {md5_1} -- the attribute sets were not "
        "actually different, so dedup behaviour is untested"
    )
    assert first.get("MD5OfMessageBody") == second.get("MD5OfMessageBody"), (
        "the two sends must carry the same body digest"
    )

    # --- dedup: same MessageId echoed, so the second send was discarded ---------------
    assert second["MessageId"] == first["MessageId"], (
        f"content-based dedup broken: attribute-varied re-send minted a new MessageId "
        f"{second['MessageId']} instead of replaying {first['MessageId']}"
    )
    assert second["SequenceNumber"] == first["SequenceNumber"], (
        f"deduplicated re-send returned SequenceNumber {second['SequenceNumber']}, "
        f"expected the original {first['SequenceNumber']}"
    )

    # --- effect absent: exactly one message exists, carrying the FIRST attributes ------
    got = _receive_all(sqs, url, expect=2, timeout_s=30)
    assert len(got) == 1, (
        f"expected 1 message after a deduplicated re-send, received {len(got)}: "
        f"{[m['MessageId'] for m in got]}"
    )
    msg = got[0]
    assert msg["MessageId"] == first["MessageId"], (
        f"delivered MessageId {msg['MessageId']} != {first['MessageId']}"
    )
    attrs = msg.get("MessageAttributes") or {}
    assert "Extra" not in attrs, (
        f"the discarded duplicate's attributes leaked onto the retained message: {sorted(attrs)}"
    )
    assert attrs.get("Attempt", {}).get("StringValue") == "one", (
        f"expected the first send's Attempt=one to be retained, got "
        f"{attrs.get('Attempt', {}).get('StringValue')!r}"
    )

    # --- control: a DIFFERENT body is not deduplicated --------------------------------
    other_body = f"{body}-distinct"
    third = sqs.send_message(
        QueueUrl=url,
        MessageBody=other_body,
        MessageGroupId=group,
        MessageAttributes={"Attempt": {"DataType": "String", "StringValue": "one"}},
    )
    assert third["MessageId"] != first["MessageId"], (
        "a different body must enqueue as a new message, but the MessageId was replayed"
    )
    control = _receive_all(sqs, url, expect=1, timeout_s=30)
    assert [m["Body"] for m in control] == [other_body], (
        f"control send did not enqueue: received {[m['Body'] for m in control]}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
