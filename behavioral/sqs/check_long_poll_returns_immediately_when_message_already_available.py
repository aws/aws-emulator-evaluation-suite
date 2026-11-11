"""long-poll-returns-immediately-when-message-already-available."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "long-poll-returns-immediately-when-message-already-available"
GROUP = "lifecycle"
SERVICES = ["sqs"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A long-poll ReceiveMessage call returns right away when a message is already sitting on the queue."""
    sqs = ctx.client("sqs")
    _tags = {"sim2real:managed": "true", "sim2real": "long-poll-returns-immediately-when-message-already-available"}
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"), tags=_tags)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    message_id = _poll_until(
        lambda: sqs.send_message(QueueUrl=url, MessageBody="already-here")["MessageId"],
        lambda mid: bool(mid),
        timeout_s=10.0,
    )
    # Give the message a moment to actually be visible for retrieval before we time the long poll.
    _poll_until(
        lambda: sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"])[
            "Attributes"
        ]["ApproximateNumberOfMessages"],
        lambda n: n != "0",
        timeout_s=15.0,
    )

    start = time.monotonic()
    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=18)
    elapsed = time.monotonic() - start

    messages = resp.get("Messages", [])
    assert any(m["MessageId"] == message_id for m in messages), (
        f"expected message {message_id!r} among returned messages, got "
        f"{[m['MessageId'] for m in messages]!r}"
    )
    # elapsed-bound: a long poll returns as soon as a message is available, not at WaitTimeSeconds.
    assert elapsed < 10, f"long poll took {elapsed:.1f}s for an already-available message (WaitTimeSeconds=18)"

    for m in messages:
        sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
