"""purge-queue-discards-in-flight-messages."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "purge-queue-discards-in-flight-messages"
GROUP = 'state'
SERVICES = ['sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": "purge-queue-in-flight"}

_N = 6
_IN_FLIGHT = 3
# PurgeQueue can take up to 60s and forbids a second purge within that window, so the settle poll
# is bounded well past it (a poll ceiling, not an asserted deadline) and the check purges once.
_PURGE_CEILING_S = 150
# The in-flight window must straddle the purge (60s) and expire inside the poll ceiling, so an
# unpurged in-flight message is receivable again by the drain.
_INFLIGHT_VIS_S = 90


def _poll(fn, pred, *, timeout_s, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _counts(sqs, url):
    a = sqs.get_queue_attributes(
        QueueUrl=url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    return (a.get("ApproximateNumberOfMessages", "?"),
            a.get("ApproximateNumberOfMessagesNotVisible", "?"))


def _drain(sqs, url, *, timeout_s, wait_s=5, empty_polls=2):
    got, empties = [], 0
    deadline = time.monotonic() + timeout_s
    while empties < empty_polls and time.monotonic() < deadline:
        batch = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s,
        ).get("Messages", [])
        if not batch:
            empties += 1
            continue
        empties = 0
        for m in batch:
            got.append(m)
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    return got


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """PurgeQueue discards in-flight (received, undeleted) messages as well as visible ones: none
    reappear after their visibility timeout lapses, and both message counters return to 0.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_PurgeQueue.html
    """
    sqs = ctx.client("sqs")
    token = uuid.uuid4().hex[:8]

    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"),
        Attributes={"VisibilityTimeout": "5"},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    bodies = [f"purge-{token}-{i}" for i in range(_N)]
    for b in bodies:
        sqs.send_message(QueueUrl=url, MessageBody=b)

    visible = _poll(lambda: _counts(sqs, url)[0], lambda v: v == str(_N),
                    timeout_s=60)
    assert visible == str(_N), (
        f"only {visible!r} of {_N} messages became visible, so the purge below has nothing to "
        f"prove"
    )

    # Put exactly _IN_FLIGHT messages in flight and do NOT delete them.
    inflight_bodies: list[str] = []
    deadline = time.monotonic() + 60
    while len(inflight_bodies) < _IN_FLIGHT and time.monotonic() < deadline:
        for m in sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=_IN_FLIGHT - len(inflight_bodies),
            WaitTimeSeconds=2,
            VisibilityTimeout=_INFLIGHT_VIS_S,
        ).get("Messages", []):
            inflight_bodies.append(m["Body"])
    assert len(inflight_bodies) == _IN_FLIGHT, (
        f"could not put {_IN_FLIGHT} messages in flight, got {len(inflight_bodies)} "
        f"({inflight_bodies!r})"
    )

    pre_visible, pre_notvisible = _poll(
        lambda: _counts(sqs, url),
        lambda c: c == (str(_N - _IN_FLIGHT), str(_IN_FLIGHT)),
        timeout_s=60,
    )
    assert pre_notvisible == str(_IN_FLIGHT), (
        f"the {_IN_FLIGHT} received messages were never in flight, so the purge below proves "
        f"nothing about in-flight messages: ApproximateNumberOfMessagesNotVisible="
        f"{pre_notvisible!r} (visible={pre_visible!r})"
    )

    sqs.purge_queue(QueueUrl=url)

    # NotVisible reaches 0 whether the purge removed the in-flight set or its visibility lapsed;
    # the drain below tells the two apart.
    _poll(lambda: _counts(sqs, url)[1], lambda v: v == "0",
          timeout_s=_PURGE_CEILING_S)

    drained = _drain(sqs, url, timeout_s=60)
    post_visible, post_notvisible = _counts(sqs, url)
    drained_bodies = [m["Body"] for m in drained]
    assert drained_bodies == [], (
        f"PurgeQueue left messages receivable: {drained_bodies!r}"
    )
    assert not (set(inflight_bodies) & set(drained_bodies)), (
        f"an IN-FLIGHT message reappeared after PurgeQueue: "
        f"{sorted(set(inflight_bodies) & set(drained_bodies))!r}"
    )
    assert (post_visible, post_notvisible) == ("0", "0"), (
        f"the message counters did not return to zero after the purge: "
        f"ApproximateNumberOfMessages={post_visible!r} "
        f"ApproximateNumberOfMessagesNotVisible={post_notvisible!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
