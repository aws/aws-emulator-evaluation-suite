"""purge-queue-removes-all-messages."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "purge-queue-removes-all-messages"
GROUP = "lifecycle"
SERVICES = ["sqs"]

_TAGS = {"sim2real:managed": "true", "sim2real": "purge-queue-removes-all-messages"}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """PurgeQueue removes all messages, visible and in-flight, within its documented async window."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    sent_ids = set()
    for i in range(5):
        resp = sqs.send_message(QueueUrl=url, MessageBody=f"purge-me-{i}")
        sent_ids.add(resp["MessageId"])

    # Make one message in-flight (received but not deleted) to prove purge covers in-flight too.
    inflight = _poll_until(
        lambda: sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=5).get("Messages", []),
        lambda msgs: len(msgs) == 1,
        timeout_s=20.0,
    )
    assert inflight[0]["MessageId"] in sent_ids, (
        f"received message {inflight[0].get('MessageId')!r} was not one of the sent ids {sent_ids!r}"
    )

    # Without this independent read, an implementation whose ReceiveMessage never actually put the
    # message in flight would satisfy every assertion below, and the check would silently degrade
    # to covering only the already-visible case.
    pre_purge_notvisible = _poll_until(
        lambda: sqs.get_queue_attributes(
            QueueUrl=url, AttributeNames=["ApproximateNumberOfMessagesNotVisible"]
        )["Attributes"]["ApproximateNumberOfMessagesNotVisible"],
        lambda v: v == "1",
        timeout_s=30.0,
    )
    assert pre_purge_notvisible == "1", (
        f"the received message was never in flight, so the purge below proves nothing about "
        f"in-flight messages: ApproximateNumberOfMessagesNotVisible={pre_purge_notvisible!r}"
    )

    sqs.purge_queue(QueueUrl=url)

    # PurgeQueue is asynchronous; per docs it can take up to 60 seconds. Poll for the observable
    # condition (no sent message is ever returned again) rather than sleeping a fixed duration.
    deadline = time.monotonic() + 65.0
    while time.monotonic() < deadline:
        leftover = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get("Messages", [])
        if any(m["MessageId"] in sent_ids for m in leftover):
            time.sleep(2)
            continue
        attrs = sqs.get_queue_attributes(
            QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"]
        )["Attributes"]
        if attrs["ApproximateNumberOfMessages"] == "0" and attrs["ApproximateNumberOfMessagesNotVisible"] == "0":
            return
        time.sleep(2)
    raise AssertionError("queue was not fully purged within 65s")


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
