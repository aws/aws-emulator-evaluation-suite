"""standard-queue-concurrent-producers-and-consumers-lose-no-message."""
from __future__ import annotations

import concurrent.futures
import hashlib
import threading
import time

from behavioral_harness import tags

CHECK = "standard-queue-concurrent-producers-and-consumers-lose-no-message"
GROUP = "concurrency"
SERVICES = ["sqs"]

_PRODUCERS = 3
_BATCHES_PER_PRODUCER = 5
_CONSUMERS = 6
_DRAIN_DEADLINE_S = 180.0
_SETTLE_S = 90.0
_TAGS = {"sim2real": "standard-queue-concurrent-producers-and-consumers-lose-no-message"}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Concurrent batch producers and consumers on one standard queue lose no message and receive no
    phantom: every body arrives with a matching MD5OfBody, no batch entry fails, and the counters
    reach 0. Duplicates are allowed on a standard queue and are not asserted either way."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-conc-pc-"),
        Attributes={"VisibilityTimeout": "60"},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    token = ctx.unique_name("b")
    lock = threading.Lock()
    sent: set[str] = set()
    received: set[str] = set()
    problems: list[str] = []
    producers_done = threading.Event()
    deadline = time.monotonic() + _DRAIN_DEADLINE_S

    def producer(p: int) -> None:
        for b in range(_BATCHES_PER_PRODUCER):
            entries = [{"Id": f"e{k}", "MessageBody": f"{token}|{p}|{b}|{k}"} for k in range(10)]
            resp = sqs.send_message_batch(QueueUrl=url, Entries=entries)
            with lock:
                if resp.get("Failed"):
                    problems.append(f"send failed: {resp['Failed']!r}")
                ok = {e["Id"] for e in resp.get("Successful", [])}
                sent.update(e["MessageBody"] for e in entries if e["Id"] in ok)

    def consumer(_: int) -> None:
        while time.monotonic() < deadline:
            with lock:
                if producers_done.is_set() and len(sent) == len(sent & received):
                    return
            msgs = sqs.receive_message(
                QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2
            ).get("Messages", [])
            if not msgs:
                continue
            with lock:
                for m in msgs:
                    if m["MD5OfBody"] != hashlib.md5(m["Body"].encode()).hexdigest():
                        problems.append(f"MD5OfBody mismatch for {m['Body']!r}")
                    received.add(m["Body"])
            resp = sqs.delete_message_batch(
                QueueUrl=url,
                Entries=[{"Id": f"d{i}", "ReceiptHandle": m["ReceiptHandle"]}
                         for i, m in enumerate(msgs)],
            )
            if resp.get("Failed"):
                with lock:
                    problems.append(f"delete failed: {resp['Failed']!r}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=_PRODUCERS + _CONSUMERS) as ex:
        consumers = [ex.submit(consumer, c) for c in range(_CONSUMERS)]
        producers = [ex.submit(producer, p) for p in range(_PRODUCERS)]
        for f in producers:
            f.result()
        producers_done.set()
        for f in consumers:
            f.result()

    expected = _PRODUCERS * _BATCHES_PER_PRODUCER * 10
    assert problems == [], f"concurrent producers/consumers hit: {problems[:5]!r}"
    assert len(sent) == expected, f"{len(sent)} of {expected} sends were acknowledged"
    missing = sent - received
    assert not missing, (
        f"{len(missing)} acknowledged message(s) were never received by any of {_CONSUMERS} "
        f"concurrent consumers within {_DRAIN_DEADLINE_S}s, e.g. {sorted(missing)[:5]!r}"
    )
    phantom = received - sent
    assert not phantom, f"consumers received bodies nobody sent: {sorted(phantom)[:5]!r}"

    counts: dict[str, str] = {}
    settle = time.monotonic() + _SETTLE_S
    while time.monotonic() < settle:
        counts = sqs.get_queue_attributes(
            QueueUrl=url,
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"]
        if counts == {"ApproximateNumberOfMessages": "0",
                      "ApproximateNumberOfMessagesNotVisible": "0"}:
            break
        time.sleep(3)
    assert counts == {"ApproximateNumberOfMessages": "0",
                      "ApproximateNumberOfMessagesNotVisible": "0"}, (
        f"after every message was received and deleted the counters read {counts!r}, "
        f"expected both 0 within {_SETTLE_S}s"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
