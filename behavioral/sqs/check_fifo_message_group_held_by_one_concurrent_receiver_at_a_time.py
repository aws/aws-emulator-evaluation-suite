"""fifo-message-group-held-by-one-concurrent-receiver-at-a-time."""
from __future__ import annotations

import concurrent.futures
import threading

from behavioral_harness import tags

CHECK = "fifo-message-group-held-by-one-concurrent-receiver-at-a-time"
GROUP = "concurrency"
SERVICES = ["sqs"]

_GROUPS = 3
_PER_GROUP = 8
_RECEIVERS = 12
_VISIBILITY_S = 300
_MAX_ROUNDS = 30
_TAGS = {"sim2real": "fifo-message-group-held-by-one-concurrent-receiver-at-a-time"}


def _concurrent_round(sqs, url: str) -> list[list[dict]]:
    """Fire one ReceiveMessage per receiver, all released together, and return every batch."""
    barrier = threading.Barrier(_RECEIVERS)

    def receive(_: int) -> list[dict]:
        barrier.wait(timeout=30)
        return sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1
        ).get("Messages", [])

    with concurrent.futures.ThreadPoolExecutor(max_workers=_RECEIVERS) as ex:
        return list(ex.map(receive, range(_RECEIVERS)))


def _groups_by_batch(batches: list[list[dict]]) -> list[dict[str, list[int]]]:
    out = []
    for batch in batches:
        held: dict[str, list[int]] = {}
        for m in batch:
            g, _, i = m["Body"].partition("|")
            held.setdefault(g, []).append(int(i))
        out.append(held)
    return out


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Concurrent receivers never split a FIFO group: its in-flight messages sit in ONE batch.

    A held group stays locked across rounds, and draining delivers each message once, in order.
    """
    sqs = ctx.client("sqs")
    token = ctx.unique_name("g")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-fifo-grp-") + ".fifo",
        Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true",
                    "VisibilityTimeout": str(_VISIBILITY_S)},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    groups = [f"{token}-{k}" for k in range(_GROUPS)]
    for i in range(_PER_GROUP):
        for g in groups:
            sqs.send_message(QueueUrl=url, MessageBody=f"{g}|{i}", MessageGroupId=g)

    # Two rounds with nothing deleted: the second round shows a held group stays locked.
    held_batches = _concurrent_round(sqs, url) + _concurrent_round(sqs, url)
    owners: dict[str, int] = {}
    for idx, held in enumerate(_groups_by_batch(held_batches)):
        for g, order in held.items():
            assert g in groups, f"a message from an unknown group {g!r} was received"
            assert g not in owners, (
                f"group {g!r} was handed to two receive batches while its messages were in flight "
                f"(batches {owners[g]} and {idx}); FIFO must lock the group to one receiver"
            )
            owners[g] = idx
            assert order == list(range(len(order))), (
                f"the first batch holding group {g!r} must hold its head messages in send order, "
                f"got indexes {order!r}"
            )
    assert owners, "two rounds of twelve concurrent receives returned no message at all"

    delivered: dict[str, list[int]] = {g: [] for g in groups}
    pending = [m for b in held_batches for m in b]
    for held in _groups_by_batch(held_batches):
        for g, order in held.items():
            delivered[g].extend(order)
    total = _GROUPS * _PER_GROUP
    for _round in range(_MAX_ROUNDS):
        for m in pending:
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
        if sum(len(v) for v in delivered.values()) >= total:
            break
        batches = _concurrent_round(sqs, url)
        seen_in_round: dict[str, int] = {}
        for idx, held in enumerate(_groups_by_batch(batches)):
            for g, order in held.items():
                assert g not in seen_in_round, (
                    f"group {g!r} appeared in two batches of one concurrent round "
                    f"({seen_in_round[g]} and {idx})"
                )
                seen_in_round[g] = idx
                nxt = len(delivered[g])
                assert order == list(range(nxt, nxt + len(order))), (
                    f"group {g!r} continued with indexes {order!r}; after {nxt} delivered "
                    f"messages the next batch must start at {nxt} and stay in order"
                )
                delivered[g].extend(order)
        pending = [m for b in batches for m in b]

    for g in groups:
        assert delivered[g] == list(range(_PER_GROUP)), (
            f"group {g!r} was delivered as {delivered[g]!r}; expected each of its {_PER_GROUP} "
            f"messages exactly once, in order, within {_MAX_ROUNDS} rounds"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
