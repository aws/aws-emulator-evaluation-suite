"""sqsbatch-send-full-width-one-invalid-entry-rejected."""
from __future__ import annotations

import hashlib
import time

from behavioral_harness import tags

CHECK = "sqsbatch-send-full-width-one-invalid-entry-rejected"
GROUP = 'errors'
SERVICES = ['sqs']

# Per-entry BatchResultErrorEntry.Code real AWS returns for an absent/empty MessageBody.
ERR_EMPTY_VALUE = "EmptyValue"

# SendMessageBatch's fixed API maximum, not an adjustable quota.
BATCH_MAX_ENTRIES = 10

# Deliberately neither first nor last, so short-circuiting and tail truncation both show.
BAD_INDEX = 4

# Entry Ids are [a-zA-Z0-9_-]{1,80}; mixed case and non-positional so they must be echoed exactly.
_IDS = [
    "Entry_00-aLPHa", "Entry_01-bRAVO", "Entry_02-cHARLIE", "Entry_03-dELTA",
    "Entry_04-eCHO", "Entry_05-fOXTROT", "Entry_06-gOLF", "Entry_07-hOTEL",
    "Entry_08-iNDIA", "Entry_09-jULIETT",
]


def _poll(fn, pred, *, timeout_s, interval_s=0.5):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _drain(sqs, url, *, timeout_s):
    """Receive-and-delete every distinct message that shows up inside timeout_s.

    Runs the full window on purpose: the window elapsing with nothing further arriving is
    the evidence that a rejected entry did NOT enqueue. Returns bodies in arrival order.
    """
    seen, bodies = set(), []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
        for msg in resp.get("Messages", []):
            if msg["MessageId"] not in seen:
                seen.add(msg["MessageId"])
                bodies.append(msg["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return bodies


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A 10-entry SendMessageBatch with one empty body splits 9/1: Successful echoes the nine Ids
    with each body's MD5, Failed names only the bad Id (EmptyValue, SenderFault), and exactly the
    nine good bodies are receivable afterwards.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SendMessageBatch.html
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    drain_s = 14

    assert len(_IDS) == BATCH_MAX_ENTRIES, f"fixture bug: {len(_IDS)} ids, want {BATCH_MAX_ENTRIES}"

    # --- positive control: a wholly valid FULL-WIDTH batch reports no failures at all ------
    ctl_bodies = {i: f"control-body-{i}" for i in range(BATCH_MAX_ENTRIES)}
    control = sqs.send_message_batch(
        QueueUrl=url,
        Entries=[{"Id": _IDS[i], "MessageBody": ctl_bodies[i]} for i in range(BATCH_MAX_ENTRIES)],
    )
    ctl_ok = {e["Id"] for e in control.get("Successful", [])}
    assert ctl_ok == set(_IDS), (
        f"a wholly valid {BATCH_MAX_ENTRIES}-entry batch reported Successful Ids "
        f"{sorted(ctl_ok)}, expected all of {sorted(_IDS)}"
    )
    assert not control.get("Failed"), f"control batch reported failures: {control.get('Failed')!r}"
    # A standard queue is unordered, so the drained bodies are compared as a set.
    drained_ctl = _drain(sqs, url, timeout_s=drain_s)
    assert set(drained_ctl) == set(ctl_bodies.values()), (
        f"control drain returned {sorted(drained_ctl)}, expected {sorted(ctl_bodies.values())}"
    )

    # --- break exactly one thing: entry 4 of 10 carries an empty MessageBody ---------------
    bodies = {i: f"kept-body-{i}" for i in range(BATCH_MAX_ENTRIES)}
    entries = [
        {"Id": _IDS[i], "MessageBody": ("" if i == BAD_INDEX else bodies[i])}
        for i in range(BATCH_MAX_ENTRIES)
    ]
    bad_id = _IDS[BAD_INDEX]
    good_ids = {_IDS[i] for i in range(BATCH_MAX_ENTRIES) if i != BAD_INDEX}
    good_bodies = {bodies[i] for i in range(BATCH_MAX_ENTRIES) if i != BAD_INDEX}

    resp = sqs.send_message_batch(QueueUrl=url, Entries=entries)
    succ = {e["Id"]: e for e in resp.get("Successful", [])}
    fail = {e["Id"]: e for e in resp.get("Failed", [])}

    assert set(succ) == good_ids, (
        f"Successful Ids {sorted(succ)} != the nine good request Ids {sorted(good_ids)}"
    )
    assert set(fail) == {bad_id}, f"Failed Ids {sorted(fail)}, expected exactly [{bad_id!r}]"
    assert set(succ) | set(fail) == set(_IDS), (
        f"envelope Ids {sorted(set(succ) | set(fail))} do not partition the request Ids "
        f"{sorted(_IDS)}"
    )

    bad = fail[bad_id]
    assert bad.get("Code") == ERR_EMPTY_VALUE, (
        f"Failed[{bad_id!r}].Code is {bad.get('Code')!r}, expected {ERR_EMPTY_VALUE!r}"
    )
    assert bad.get("SenderFault") is True, (
        f"Failed[{bad_id!r}].SenderFault must be True for a client error (a retry can never "
        f"succeed), got {bad.get('SenderFault')!r}"
    )
    assert bad.get("Message") == f"No Value Found for SendMessageBatchRequestEntry.{BAD_INDEX + 1}.MessageBody.", (
        f"Failed[{bad_id!r}].Message is {bad.get('Message')!r}"
    )

    # Each Successful entry's digest must be of the body THAT Id carried.
    for i in range(BATCH_MAX_ENTRIES):
        if i == BAD_INDEX:
            continue
        entry = succ[_IDS[i]]
        want = hashlib.md5(bodies[i].encode()).hexdigest()
        assert entry.get("MD5OfMessageBody") == want, (
            f"Successful[{_IDS[i]!r}].MD5OfMessageBody is {entry.get('MD5OfMessageBody')!r}, "
            f"expected md5({bodies[i]!r}) = {want!r}"
        )
        assert entry.get("MessageId"), f"Successful[{_IDS[i]!r}] carries no MessageId"
    minted = [succ[i]["MessageId"] for i in sorted(succ)]
    assert len(set(minted)) == len(good_ids), (
        f"the nine Successful entries minted {len(set(minted))} distinct MessageIds: {minted}"
    )

    # --- effect, and effect-absent: exactly the nine good bodies are receivable ------------
    drained = _drain(sqs, url, timeout_s=drain_s)
    assert set(drained) == good_bodies, (
        f"drained {sorted(drained)}, expected exactly the nine good bodies "
        f"{sorted(good_bodies)}"
    )
    assert len(drained) == len(good_ids), (
        f"drained {len(drained)} distinct messages from a batch whose response reported "
        f"{len(good_ids)} Successful entries: {drained}"
    )
    assert "" not in drained, (
        f"an empty-bodied message was receivable, so the entry AWS reported Failed with "
        f"{ERR_EMPTY_VALUE} enqueued anyway: {drained}"
    )
    remaining = _poll(
        lambda: sqs.get_queue_attributes(
            QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"]
        )["Attributes"]["ApproximateNumberOfMessages"],
        lambda v: v == "0",
        timeout_s=30,
    )
    assert remaining == "0", (
        f"queue still reports {remaining!r} visible messages after draining all nine"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
