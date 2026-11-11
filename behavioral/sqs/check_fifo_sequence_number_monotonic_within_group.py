"""fifo-sequence-number-monotonic-within-group."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "fifo-sequence-number-monotonic-within-group"
GROUP = 'fifo'
SERVICES = ['sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": "fifo-sequence-number-monotonic-within-group"}


def _receive_all(sqs, url, *, expect, timeout_s, delete=True):
    """Receive up to `expect` distinct messages within timeout_s, preserving arrival order."""
    seen, msgs = set(), []
    deadline = time.monotonic() + timeout_s
    while len(msgs) < expect and time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=1,
            MessageSystemAttributeNames=["SequenceNumber", "MessageGroupId"],
        )
        for msg in resp.get("Messages", []):
            if msg["MessageId"] not in seen:
                seen.add(msg["MessageId"])
                msgs.append(msg)
            if delete:
                sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return msgs


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """FIFO SequenceNumber strictly increases with send order within each MessageGroupId.

    The number SendMessage echoes is the one on the received message; delivery keeps group order.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + ".fifo",
        Attributes={"FifoQueue": "true"},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    token = uuid.uuid4().hex[:8]
    # Interleaved sends across two groups, so a per-group sequence cannot be faked by
    # replaying the global send order.
    plan = [("A", 0), ("B", 0), ("A", 1), ("A", 2), ("B", 1), ("A", 3)]
    sent = []  # (group, body, sequence_number) in send order
    for group, idx in plan:
        body = f"seq-{group}-{idx}-{token}"
        resp = sqs.send_message(
            QueueUrl=url,
            MessageBody=body,
            MessageGroupId=f"grp-{group}-{token}",
            MessageDeduplicationId=f"{token}-{group}-{idx}",
        )
        seq = resp.get("SequenceNumber")
        assert seq and seq.isdigit(), f"SendMessage returned no numeric SequenceNumber: {seq!r}"
        sent.append((group, body, seq))

    for group in ("A", "B"):
        seqs = [int(s) for g, _b, s in sent if g == group]
        assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs), (
            f"group {group} SequenceNumbers are not strictly increasing in send order: {seqs}"
        )
    all_seqs = [s for _g, _b, s in sent]
    assert len(set(all_seqs)) == len(all_seqs), f"SequenceNumber reused across the queue: {all_seqs}"

    received = _receive_all(sqs, url, expect=len(plan), timeout_s=45)
    assert len(received) == len(plan), (
        f"expected {len(plan)} messages, received {len(received)}: "
        f"{[m['Body'] for m in received]}"
    )
    by_body = {}
    for msg in received:
        attrs = msg.get("Attributes") or {}
        assert "SequenceNumber" in attrs, (
            f"received message carries no SequenceNumber system attribute: {sorted(attrs)}"
        )
        by_body[msg["Body"]] = attrs["SequenceNumber"]
    for _group, body, seq in sent:
        assert by_body.get(body) == seq, (
            f"{body}: SendMessage echoed SequenceNumber {seq} but the received message "
            f"carries {by_body.get(body)!r}"
        )
    for group in ("A", "B"):
        want = [body for g, body, _s in sent if g == group]
        got = [m["Body"] for m in received if m["Body"] in set(want)]
        assert got == want, f"group {group} delivery order {got} != send order {want}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
