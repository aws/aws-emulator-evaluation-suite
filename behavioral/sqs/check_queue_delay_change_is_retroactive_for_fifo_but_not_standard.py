"""queue-delay-change-is-retroactive-for-fifo-but-not-standard."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "queue-delay-change-is-retroactive-for-fifo-but-not-standard"
GROUP = 'state'
SERVICES = ['sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": "queue-delay-retroactivity"}

# The original delay is the 900s maximum, so a message sent under it cannot become receivable
# inside this check's observation window unless the queue-level change reached it.
_ORIGINAL_DELAY_S = 900
# Bound on how long the lowered delay may take to propagate and release the messages it governs.
_CONVERGE_S = 150.0


def _receive(sqs, url, wait_s=2):
    return sqs.receive_message(
        QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s,
    ).get("Messages", [])


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Lowering a queue's DelaySeconds releases messages already on a FIFO queue, but on a standard
    queue only messages sent after the change see it; the original message stays withheld.
    """
    sqs = ctx.client("sqs")
    token = uuid.uuid4().hex[:8]

    std_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + "-std",
        Attributes={"DelaySeconds": str(_ORIGINAL_DELAY_S)},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=std_url))

    fifo_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + ".fifo",
        Attributes={"FifoQueue": "true", "DelaySeconds": str(_ORIGINAL_DELAY_S)},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=fifo_url))

    for url in (std_url, fifo_url):
        got = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["DelaySeconds"])[
            "Attributes"]["DelaySeconds"]
        assert got == str(_ORIGINAL_DELAY_S), (
            f"queue did not take DelaySeconds={_ORIGINAL_DELAY_S}: {got!r}")

    std_old = f"std-before-change-{token}"
    fifo_old = f"fifo-before-change-{token}"
    sqs.send_message(QueueUrl=std_url, MessageBody=std_old)
    sqs.send_message(QueueUrl=fifo_url, MessageBody=fifo_old, MessageGroupId="g",
                     MessageDeduplicationId=f"old-{token}")

    # Both are withheld under the original delay before anything changes.
    before = [m["Body"] for m in _receive(sqs, std_url) + _receive(sqs, fifo_url)]
    assert before == [], f"a message under a {_ORIGINAL_DELAY_S}s delay was delivered: {before!r}"

    sqs.set_queue_attributes(QueueUrl=std_url, Attributes={"DelaySeconds": "0"})
    sqs.set_queue_attributes(QueueUrl=fifo_url, Attributes={"DelaySeconds": "0"})

    # FIFO: the message already on the queue is released by the change.
    fifo_seen: list[str] = []
    deadline = time.monotonic() + _CONVERGE_S
    while fifo_old not in fifo_seen and time.monotonic() < deadline:
        for m in _receive(sqs, fifo_url, wait_s=5):
            fifo_seen.append(m["Body"])
            sqs.delete_message(QueueUrl=fifo_url, ReceiptHandle=m["ReceiptHandle"])
    assert fifo_seen == [fifo_old], (
        f"lowering DelaySeconds on a FIFO queue must release the message already on it within "
        f"{_CONVERGE_S:.0f}s; received {fifo_seen!r}, expected {[fifo_old]!r}")

    # Standard: new messages see the change, the old one does not.
    std_seen: list[str] = []
    probes: list[str] = []
    deadline = time.monotonic() + _CONVERGE_S
    while not any(b in std_seen for b in probes) and time.monotonic() < deadline:
        probe = f"std-after-change-{len(probes)}-{token}"
        probes.append(probe)
        sqs.send_message(QueueUrl=std_url, MessageBody=probe)
        for m in _receive(sqs, std_url, wait_s=3):
            std_seen.append(m["Body"])
            sqs.delete_message(QueueUrl=std_url, ReceiptHandle=m["ReceiptHandle"])
    arrived = [b for b in probes if b in std_seen]
    assert arrived, (
        f"no message sent after DelaySeconds=0 on the standard queue arrived within "
        f"{_CONVERGE_S:.0f}s ({len(probes)} probes sent), so the change never took effect")
    # Give the original message the same window again after the change is proven live.
    settle = time.monotonic() + 15
    while time.monotonic() < settle:
        for m in _receive(sqs, std_url, wait_s=5):
            std_seen.append(m["Body"])
            sqs.delete_message(QueueUrl=std_url, ReceiptHandle=m["ReceiptHandle"])
    assert std_old not in std_seen, (
        f"lowering DelaySeconds on a STANDARD queue released a message sent before the change; "
        f"the per-queue delay is not retroactive there. Received {sorted(std_seen)!r}")
    assert set(std_seen) <= set(probes), (
        f"standard queue delivered bodies nobody sent after the change: "
        f"{sorted(set(std_seen) - set(probes))!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
