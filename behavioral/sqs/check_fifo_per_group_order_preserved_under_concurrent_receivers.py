"""fifo-per-group-order-preserved-under-concurrent-receivers."""
from __future__ import annotations

import concurrent.futures
import threading
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fifo-per-group-order-preserved-under-concurrent-receivers"
GROUP = 'concurrency'
SERVICES = ['sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": "fifo-order-under-concurrency"}

_GROUPS = 3
_PER_GROUP = 6
_TOTAL = _GROUPS * _PER_GROUP
_WORKERS = 4
# VisibilityTimeout must be comfortably LONGER than the drain deadline. Every worker deletes each
# message the moment it has recorded it, so a redelivery can only happen if a worker stalls for
# the whole visibility window -- and a redelivery would be a legitimate SQS behaviour that the
# "no message twice" assertion below would misread as a defect. Keeping the deadline under the
# timeout is what makes that assertion an invariant rather than a race.
_VISIBILITY_S = 120
_DRAIN_DEADLINE_S = 60


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Four concurrent receivers draining a FIFO queue of three groups see each group in send order
    and no message twice; group blocking is what makes FIFO usable by a consumer fleet.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/FIFO-queues-understanding-logic.html
    """
    # No exactly-once or per-worker distribution claim: one worker receiving all 18 is faithful.
    sqs = ctx.client("sqs")
    token = uuid.uuid4().hex[:8]

    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + ".fifo",
        Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true",
                    "VisibilityTimeout": str(_VISIBILITY_S)},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    groups = [f"g{i}-{token}" for i in range(_GROUPS)]
    # Sent sequentially, per group, so the intended order is unambiguous. SequenceNumbers are
    # recorded per group and asserted strictly increasing, which is what pins "send order" to
    # something the service itself reports rather than to this loop's own ordering.
    sent_seqs: dict[str, list[str]] = {g: [] for g in groups}
    for idx in range(_PER_GROUP):
        for g in groups:
            r = sqs.send_message(QueueUrl=url, MessageBody=f"{g}|{idx}", MessageGroupId=g)
            sent_seqs[g].append(r["SequenceNumber"])
    for g in groups:
        assert sent_seqs[g] == sorted(sent_seqs[g]) and len(set(sent_seqs[g])) == _PER_GROUP, (
            f"group {g!r} SequenceNumbers are not strictly increasing in send order, so 'send "
            f"order' is undefined below: {sent_seqs[g]!r}"
        )

    lock = threading.Lock()
    collected: list[tuple[int, str, int]] = []   # (worker, group, index)
    errors: list[str] = []
    deadline = time.monotonic() + _DRAIN_DEADLINE_S

    def worker(wid: int) -> None:
        while time.monotonic() < deadline:
            with lock:
                if len(collected) >= _TOTAL:
                    return
            try:
                batch = sqs.receive_message(
                    QueueUrl=url, MaxNumberOfMessages=2, WaitTimeSeconds=5,
                ).get("Messages", [])
            except ClientError as exc:
                with lock:
                    errors.append(exc.response.get("Error", {}).get("Code") or "?")
                return
            if not batch:
                continue
            # Record the whole batch UNDER THE LOCK, then delete. The order matters: a group stays
            # blocked until its in-flight message is deleted, so recording before deleting is what
            # guarantees that `collected` observes each group in delivery order. Deleting first
            # would let another worker receive and record the group's NEXT message before this
            # worker had recorded the current one -- a bookkeeping race that would read as a FIFO
            # ordering violation.
            with lock:
                for m in batch:
                    g, _, i = m["Body"].partition("|")
                    collected.append((wid, g, int(i)))
            for m in batch:
                try:
                    sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
                except ClientError as exc:
                    with lock:
                        errors.append(exc.response.get("Error", {}).get("Code") or "?")

    ex = concurrent.futures.ThreadPoolExecutor(max_workers=_WORKERS)
    try:
        futures = [ex.submit(worker, w) for w in range(_WORKERS)]
        for f in futures:
            f.result()
    finally:
        # wait=True so no worker is still calling receive_message against a queue the cleanup
        # registered above is about to delete.
        ex.shutdown(wait=True)

    assert errors == [], f"concurrent receivers raised: {errors!r}"
    assert len(collected) == _TOTAL, (
        f"the concurrent receivers drained {len(collected)} of {_TOTAL} messages before the "
        f"{_DRAIN_DEADLINE_S}s deadline: {sorted((g, i) for _, g, i in collected)!r}"
    )
    assert len({(g, i) for _, g, i in collected}) == _TOTAL, (
        f"a FIFO message was delivered to more than one concurrent receiver: "
        f"{sorted((w, g, i) for w, g, i in collected)!r}"
    )

    per_group_order: dict[str, list[int]] = {g: [] for g in groups}
    for _, g, i in collected:
        assert g in per_group_order, f"a message arrived from an unknown group {g!r}"
        per_group_order[g].append(i)
    for g, order in per_group_order.items():
        assert order == sorted(order), (
            f"per-group FIFO order was violated under {_WORKERS} concurrent receivers: group "
            f"{g!r} was observed as {order!r}, expected {sorted(order)!r}"
        )
        assert order == list(range(_PER_GROUP)), (
            f"group {g!r} did not deliver all {_PER_GROUP} of its messages exactly once: "
            f"{order!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
