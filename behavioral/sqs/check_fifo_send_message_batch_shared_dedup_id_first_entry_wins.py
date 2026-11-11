"""fifo-send-message-batch-shared-dedup-id-first-entry-wins."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "fifo-send-message-batch-shared-dedup-id-first-entry-wins"
GROUP = "fifo"
SERVICES = ["sqs"]

_TAGS = {"sim2real": "fifo-send-message-batch-shared-dedup-id-first-entry-wins"}


def _drain(sqs, url, *, min_count, timeout_s=20.0):
    seen: list[dict] = []
    deadline = time.monotonic() + timeout_s
    idle = 0
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get(
            "Messages", [])
        if not msgs:
            idle += 1
            if len(seen) >= min_count and idle >= 2:
                break
            continue
        idle = 0
        for m in msgs:
            seen.append(m)
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    return seen


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two batch entries sharing a dedup id both succeed with one MessageId and SequenceNumber.

    Each keeps its own MD5OfMessageBody, but only the FIRST entry by position is delivered.
    """
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-fifodup-") + ".fifo"
    url = sqs.create_queue(
        QueueName=name,
        Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "false"},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    dedup_id = uuid.uuid4().hex
    resp = sqs.send_message_batch(QueueUrl=url, Entries=[
        {"Id": "z-later-id", "MessageBody": "first-position-body",
         "MessageGroupId": "g1", "MessageDeduplicationId": dedup_id},
        {"Id": "a-earlier-id", "MessageBody": "second-position-body",
         "MessageGroupId": "g1", "MessageDeduplicationId": dedup_id},
    ])
    assert not resp.get("Failed"), (
        f"a batch with two entries sharing one dedup id answered Failed={resp.get('Failed')!r}"
    )
    successful = {e["Id"]: e for e in resp.get("Successful", [])}
    assert set(successful) == {"z-later-id", "a-earlier-id"}, (
        f"Successful Ids were {sorted(successful)}, expected both entries"
    )
    message_ids = {e["MessageId"] for e in successful.values()}
    sequence_numbers = {e["SequenceNumber"] for e in successful.values()}
    assert len(message_ids) == 1, (
        f"the two entries minted distinct MessageIds {message_ids!r}; sharing a dedup id in "
        f"one batch call must resolve to the SAME message"
    )
    assert len(sequence_numbers) == 1, (
        f"the two entries minted distinct SequenceNumbers {sequence_numbers!r}; they must share "
        f"the one FIFO sequence position their shared dedup id resolved to"
    )
    md5s = {eid: e["MD5OfMessageBody"] for eid, e in successful.items()}
    assert md5s["z-later-id"] != md5s["a-earlier-id"], (
        f"MD5OfMessageBody was identical for both entries ({md5s!r}); each entry's digest must "
        f"reflect its OWN body, even though only one body is ever delivered"
    )

    delivered = _drain(sqs, url, min_count=1)
    bodies = [m["Body"] for m in delivered]
    assert bodies == ["first-position-body"], (
        f"the queue delivered {bodies!r}; a shared dedup id inside one batch call must resolve "
        f"to the FIRST entry BY POSITION ('first-position-body'), not the second, and not both"
    )

    # A fresh dedup id is not swallowed: the dedup window is scoped to the id, not the batch.
    other = sqs.send_message_batch(QueueUrl=url, Entries=[
        {"Id": "ctrl", "MessageBody": "control-body", "MessageGroupId": "g1",
         "MessageDeduplicationId": uuid.uuid4().hex},
    ])
    assert not other.get("Failed"), f"control send answered Failed={other.get('Failed')!r}"
    control_delivered = _drain(sqs, url, min_count=1)
    assert [m["Body"] for m in control_delivered] == ["control-body"], (
        f"the control send delivered {[m['Body'] for m in control_delivered]!r}, expected "
        f"exactly ['control-body']"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
