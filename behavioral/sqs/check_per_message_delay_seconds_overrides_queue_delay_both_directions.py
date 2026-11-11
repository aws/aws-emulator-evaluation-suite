"""per-message-delay-seconds-overrides-queue-delay-both-directions."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "per-message-delay-seconds-overrides-queue-delay-both-directions"
GROUP = 'invariants'
SERVICES = ['sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": "delay-seconds-override"}

_DELAY_S = 15
# A 15s-delayed message cannot be receivable within a few seconds, so its absence is an invariant;
# the immediate drain retries for presence but stays well inside _DELAY_S.
_IMMEDIATE_POLLS = 2
_IMMEDIATE_WAIT_S = 2


def _drain(sqs, url, into, *, timeout_s, wait_s, empty_polls):
    """Receive-and-delete into the set `into` until `empty_polls` consecutive empties or deadline."""
    empties = 0
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
            into.add(m["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    return into


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A per-message DelaySeconds overrides the queue's in both directions: DelaySeconds=0 on a
    15s-delay queue is receivable at once, and DelaySeconds=15 on a 0s queue is not.
    """
    sqs = ctx.client("sqs")
    token = uuid.uuid4().hex[:8]

    url_slow = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + "-slow",
        Attributes={"DelaySeconds": str(_DELAY_S)},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url_slow))

    url_fast = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + "-fast", tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url_fast))

    slow_attrs = sqs.get_queue_attributes(
        QueueUrl=url_slow, AttributeNames=["All"])["Attributes"]
    assert slow_attrs.get("DelaySeconds") == str(_DELAY_S), (
        f"the delayed queue did not take DelaySeconds={_DELAY_S}, so neither override direction "
        f"below is being tested: DelaySeconds={slow_attrs.get('DelaySeconds')!r}"
    )
    fast_attrs = sqs.get_queue_attributes(
        QueueUrl=url_fast, AttributeNames=["All"])["Attributes"]
    assert fast_attrs.get("DelaySeconds") == "0", (
        f"the undelayed queue must carry the DEFAULT DelaySeconds=0: "
        f"{fast_attrs.get('DelaySeconds')!r}"
    )

    # An explicit 0 must not be treated as "not supplied" and fall back to the queue's delay.
    marker_a = f"a-msgdelay0-on-slowq-{token}"     # explicit 0 must BEAT the queue's 15
    marker_b = f"b-inherits15-on-slowq-{token}"    # no parameter -> inherits the queue's 15
    marker_c = f"c-msgdelay15-on-fastq-{token}"    # explicit 15 must BEAT the queue's 0
    marker_d = f"d-inherits0-on-fastq-{token}"     # no parameter -> inherits the queue's 0

    sqs.send_message(QueueUrl=url_slow, MessageBody=marker_a, DelaySeconds=0)
    sqs.send_message(QueueUrl=url_slow, MessageBody=marker_b)
    sqs.send_message(QueueUrl=url_fast, MessageBody=marker_c, DelaySeconds=_DELAY_S)
    sqs.send_message(QueueUrl=url_fast, MessageBody=marker_d)

    # --- immediate phase: bounded well inside the 15s boundary -------------------------
    immediate_slow: set[str] = set()
    immediate_fast: set[str] = set()
    _drain(sqs, url_slow, immediate_slow, timeout_s=_IMMEDIATE_POLLS * _IMMEDIATE_WAIT_S + 2,
           wait_s=_IMMEDIATE_WAIT_S, empty_polls=_IMMEDIATE_POLLS)
    _drain(sqs, url_fast, immediate_fast, timeout_s=_IMMEDIATE_POLLS * _IMMEDIATE_WAIT_S + 2,
           wait_s=_IMMEDIATE_WAIT_S, empty_polls=_IMMEDIATE_POLLS)

    assert immediate_slow == {marker_a}, (
        f"on a DelaySeconds={_DELAY_S} queue, exactly the message that overrode with "
        f"DelaySeconds=0 may be immediately receivable: got {sorted(immediate_slow)!r}, expected "
        f"{[marker_a]!r}"
    )
    assert immediate_fast == {marker_d}, (
        f"on a DelaySeconds=0 queue, the message that overrode with DelaySeconds={_DELAY_S} must "
        f"NOT be immediately receivable: got {sorted(immediate_fast)!r}, expected {[marker_d]!r}"
    )

    # --- eventual phase: both delayed messages must arrive -----------------------------
    eventual_slow = _drain(sqs, url_slow, set(immediate_slow),
                           timeout_s=90, wait_s=5, empty_polls=3)
    eventual_fast = _drain(sqs, url_fast, set(immediate_fast),
                           timeout_s=90, wait_s=5, empty_polls=3)

    assert eventual_slow == {marker_a, marker_b}, (
        f"the queue-delayed message never arrived on the delayed queue: got "
        f"{sorted(eventual_slow)!r}, expected {sorted([marker_a, marker_b])!r}"
    )
    assert eventual_fast == {marker_c, marker_d}, (
        f"the message-delayed message never arrived on the undelayed queue: got "
        f"{sorted(eventual_fast)!r}, expected {sorted([marker_c, marker_d])!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
