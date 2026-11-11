"""batch-entry-over-queue-max-message-size-fails-alone."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-entry-over-queue-max-message-size-fails-alone"
GROUP = "limits"
SERVICES = ["sqs"]

_LIMIT = 1024
_ENTRY_OVERSIZE_MESSAGE = (
    "One or more parameters cannot be validated. Reason: Message must be shorter than 1024 bytes."
)


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A queue's MaximumMessageSize bounds each SendMessageBatch entry, not the batch: on a 1024-byte
    queue a 1025-byte entry fails alone while its siblings land, and two 1000-byte entries (2000
    bytes in total) are accepted whole.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-batchsize-"),
        Attributes={"MaximumMessageSize": str(_LIMIT)},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    limit = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["MaximumMessageSize"])[
        "Attributes"
    ]["MaximumMessageSize"]
    assert limit == str(_LIMIT), f"MaximumMessageSize read back as {limit!r}, expected {str(_LIMIT)!r}"

    mixed = sqs.send_message_batch(
        QueueUrl=url,
        Entries=[
            {"Id": "fits", "MessageBody": "a" * _LIMIT},
            {"Id": "oversize", "MessageBody": "b" * (_LIMIT + 1)},
        ],
    )
    ok_ids = [e["Id"] for e in mixed.get("Successful", [])]
    failed = {e["Id"]: e for e in mixed.get("Failed", [])}
    assert ok_ids == ["fits"] and sorted(failed) == ["oversize"], (
        f"expected 'fits' to succeed and only 'oversize' to fail; Successful ids {ok_ids!r}, "
        f"Failed {mixed.get('Failed')!r}"
    )
    bad = failed["oversize"]
    assert (bad.get("Code"), bad.get("SenderFault"), bad.get("Message")) == (
        "InvalidParameterValue", True, _ENTRY_OVERSIZE_MESSAGE
    ), f"the oversize entry failed with {bad!r}"

    whole = sqs.send_message_batch(
        QueueUrl=url,
        Entries=[
            {"Id": "c", "MessageBody": "c" * 1000},
            {"Id": "d", "MessageBody": "d" * 1000},
        ],
    )
    assert sorted(e["Id"] for e in whole.get("Successful", [])) == ["c", "d"] and not whole.get("Failed"), (
        f"a batch whose entries each fit but whose total (2000 bytes) exceeds the queue's "
        f"{_LIMIT}-byte MaximumMessageSize must be accepted whole; Successful "
        f"{whole.get('Successful')!r}, Failed {whole.get('Failed')!r}"
    )

    got: list[tuple[str, int]] = []
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get(
            "Messages", []
        )
        if not msgs and len(got) >= 3:
            break
        for m in msgs:
            got.append((m["Body"][0], len(m["Body"])))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    assert sorted(got) == [("a", _LIMIT), ("c", 1000), ("d", 1000)], (
        f"the queue must hold exactly the three accepted bodies and not the oversize one; "
        f"received (first char, length) {sorted(got)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
