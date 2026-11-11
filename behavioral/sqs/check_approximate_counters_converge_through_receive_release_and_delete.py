"""approximate-counters-converge-through-receive-release-and-delete."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "approximate-counters-converge-through-receive-release-and-delete"
GROUP = 'state'
SERVICES = ['sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": "approx-counter-transitions"}

# The GetQueueAttributes reference allows the approximate counters about a minute to settle.
_CONVERGE_S = 120.0
_COUNTERS = ("ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible",
             "ApproximateNumberOfMessagesDelayed")


def _read(sqs, url):
    a = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=list(_COUNTERS))["Attributes"]
    return tuple(int(a[k]) for k in _COUNTERS)


def _converge(sqs, url, want, stage):
    got = _read(sqs, url)
    deadline = time.monotonic() + _CONVERGE_S
    while got != want and time.monotonic() < deadline:
        time.sleep(3)
        got = _read(sqs, url)
    assert got == want, (
        f"{stage}: (visible, in-flight, delayed) did not converge to {want!r} within "
        f"{_CONVERGE_S:.0f}s; last read {got!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The (visible, in-flight, delayed) approximate counters converge after each change: five sent
    (5, 0, 0), three received (2, 3, 0), one released (3, 2, 0), one deleted (3, 1, 0), and the
    rest drained (0, 0, 0)."""
    sqs = ctx.client("sqs")
    token = uuid.uuid4().hex[:8]
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"),
        Attributes={"VisibilityTimeout": "600"}, tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    _converge(sqs, url, (0, 0, 0), "fresh queue")

    bodies = [f"count-{i}-{token}" for i in range(5)]
    sqs.send_message_batch(QueueUrl=url, Entries=[
        {"Id": str(i), "MessageBody": b} for i, b in enumerate(bodies)])
    _converge(sqs, url, (5, 0, 0), "after sending five")

    held: list[dict] = []
    deadline = time.monotonic() + 60
    while len(held) < 3 and time.monotonic() < deadline:
        held += sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=3 - len(held),
                                    WaitTimeSeconds=2).get("Messages", [])
    assert len(held) == 3, f"expected to take three messages in flight, got {len(held)}"
    _converge(sqs, url, (2, 3, 0), "after taking three in flight")

    sqs.change_message_visibility(QueueUrl=url, ReceiptHandle=held[0]["ReceiptHandle"],
                                  VisibilityTimeout=0)
    _converge(sqs, url, (3, 2, 0), "after releasing one with VisibilityTimeout=0")

    sqs.delete_message(QueueUrl=url, ReceiptHandle=held[1]["ReceiptHandle"])
    _converge(sqs, url, (3, 1, 0), "after deleting one in-flight message")

    sqs.delete_message(QueueUrl=url, ReceiptHandle=held[2]["ReceiptHandle"])
    seen = {held[1]["Body"], held[2]["Body"]}
    deadline = time.monotonic() + 60
    while len(seen) < 5 and time.monotonic() < deadline:
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                     WaitTimeSeconds=2).get("Messages", []):
            seen.add(m["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    assert seen == set(bodies), f"drain saw {sorted(seen)!r}, expected {sorted(bodies)!r}"
    _converge(sqs, url, (0, 0, 0), "after deleting everything")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
