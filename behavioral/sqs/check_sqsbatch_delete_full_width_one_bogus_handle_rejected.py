"""sqsbatch-delete-full-width-one-bogus-handle-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "sqsbatch-delete-full-width-one-bogus-handle-rejected"
GROUP = 'errors'
SERVICES = ['sqs']

# Per-entry BatchResultErrorEntry.Code real AWS returns for a syntactically bogus handle.
ERR_RECEIPT_HANDLE_INVALID = "ReceiptHandleIsInvalid"

# DeleteMessageBatch's fixed API maximum. A fixed API constant, not a Service-Quotas value.
BATCH_MAX_ENTRIES = 10

# Which of the ten entries gets the bogus handle. Neither first nor last, so a target that
# aborts at the first bad entry and one that ignores the tail both diverge.
BAD_INDEX = 7

# Long enough to receive all ten before any handle expires, short enough that the one
# surviving message redelivers inside the check. Read back off the queue rather than assumed.
VISIBILITY_TIMEOUT_S = 10

_BOGUS_HANDLE = "AQEBsim2real-not-a-real-receipt-handle-0000000000"

_TAGS = {"sim2real:managed": "true", "sim2real": CHECK}


def _poll(fn, pred, *, timeout_s, interval_s=0.5):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _receive_by_body(sqs, url, *, want, timeout_s):
    """Receive until every body in `want` has been seen once; return {body: ReceiptHandle}.

    Does not delete: the caller owns the handles. Returns whatever it has when the window
    closes, so the caller's assert names the shortfall.
    """
    handles = {}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and len(handles) < len(want):
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
        for msg in resp.get("Messages", []):
            handles.setdefault(msg["Body"], msg["ReceiptHandle"])
    return handles


def _observe(sqs, url, *, timeout_s):
    """Collect the bodies of every distinct message that becomes visible inside timeout_s,
    deleting each so it is counted once. The full window is always run: the window closing
    with nothing further arriving is the effect-absent evidence."""
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


# timing:real-time — visibility: 10 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
@tags(
    "axis:rejection",
    "cap:c2",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A 10-entry DeleteMessageBatch with one bogus receipt handle deletes the other nine: Failed
    names only that Id (ReceiptHandleIsInvalid, SenderFault=true) and only its message redelivers.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_DeleteMessageBatch.html
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"),
        Attributes={"VisibilityTimeout": str(VISIBILITY_TIMEOUT_S)},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    vis = int(sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["VisibilityTimeout"]
    )["Attributes"]["VisibilityTimeout"])
    assert vis == VISIBILITY_TIMEOUT_S, (
        f"queue reports VisibilityTimeout={vis!r}, expected {VISIBILITY_TIMEOUT_S}; the "
        f"redelivery window below is derived from this value"
    )
    recv_s = 12
    # Windows derived from the queue's reported timeout: `empty_s` outlasts one timeout;
    # `redeliver_s` also leaves room for the redelivery itself, so it doubles it.
    empty_s = vis + 5
    redeliver_s = vis * 2

    def _send_ten(prefix):
        want = [f"{prefix}-{i}" for i in range(BATCH_MAX_ENTRIES)]
        resp = sqs.send_message_batch(
            QueueUrl=url,
            Entries=[{"Id": f"s{i}", "MessageBody": want[i]} for i in range(BATCH_MAX_ENTRIES)],
        )
        assert not resp.get("Failed"), f"setup send batch {prefix!r} failed: {resp.get('Failed')!r}"
        assert len(resp.get("Successful", [])) == BATCH_MAX_ENTRIES, (
            f"setup send batch {prefix!r} enqueued {len(resp.get('Successful', []))} of "
            f"{BATCH_MAX_ENTRIES}"
        )
        return want

    # --- positive control: all ten handles valid -> ten Successful, queue empties -----------
    ctl_bodies = _send_ten("control")
    ctl_handles = _receive_by_body(sqs, url, want=ctl_bodies, timeout_s=recv_s)
    assert set(ctl_handles) == set(ctl_bodies), (
        f"control receive got {sorted(ctl_handles)} of {sorted(ctl_bodies)} within {recv_s}s"
    )
    ctl_resp = sqs.delete_message_batch(
        QueueUrl=url,
        Entries=[{"Id": f"c{i}", "ReceiptHandle": ctl_handles[ctl_bodies[i]]}
                 for i in range(BATCH_MAX_ENTRIES)],
    )
    ctl_ok = {e["Id"] for e in ctl_resp.get("Successful", [])}
    assert ctl_ok == {f"c{i}" for i in range(BATCH_MAX_ENTRIES)}, (
        f"control DeleteMessageBatch Successful Ids {sorted(ctl_ok)}, expected all ten"
    )
    assert not ctl_resp.get("Failed"), f"control delete reported {ctl_resp.get('Failed')!r}"
    stragglers = _observe(sqs, url, timeout_s=empty_s)
    assert stragglers == [], (
        f"after a wholly successful full-width delete the queue redelivered {stragglers}; "
        f"the Successful entries were a response-only claim"
    )

    # --- one entry (BAD_INDEX) carries a bogus receipt handle -------------------------------
    bodies = _send_ten("round2")
    handles = _receive_by_body(sqs, url, want=bodies, timeout_s=recv_s)
    assert set(handles) == set(bodies), (
        f"receive got {sorted(handles)} of {sorted(bodies)} within {recv_s}s; all ten must be "
        f"in flight before the batch delete"
    )
    survivor = bodies[BAD_INDEX]
    deleted_bodies = {bodies[i] for i in range(BATCH_MAX_ENTRIES) if i != BAD_INDEX}
    bad_id = f"d{BAD_INDEX}"
    entries = [
        {"Id": f"d{i}",
         "ReceiptHandle": (_BOGUS_HANDLE if i == BAD_INDEX else handles[bodies[i]])}
        for i in range(BATCH_MAX_ENTRIES)
    ]

    resp = sqs.delete_message_batch(QueueUrl=url, Entries=entries)
    succ = {e["Id"] for e in resp.get("Successful", [])}
    fail = {e["Id"]: e for e in resp.get("Failed", [])}

    assert succ == {f"d{i}" for i in range(BATCH_MAX_ENTRIES) if i != BAD_INDEX}, (
        f"Successful Ids {sorted(succ)} != the nine entries with valid handles"
    )
    assert set(fail) == {bad_id}, f"Failed Ids {sorted(fail)}, expected exactly [{bad_id!r}]"
    assert succ | set(fail) == {f"d{i}" for i in range(BATCH_MAX_ENTRIES)}, (
        f"envelope Ids {sorted(succ | set(fail))} do not partition the ten request Ids"
    )

    bad = fail[bad_id]
    assert bad.get("Code") == ERR_RECEIPT_HANDLE_INVALID, (
        f"Failed[{bad_id!r}].Code is {bad.get('Code')!r}, expected "
        f"{ERR_RECEIPT_HANDLE_INVALID!r}"
    )
    assert bad.get("SenderFault") is True, (
        f"Failed[{bad_id!r}].SenderFault must be True for a malformed handle, got "
        f"{bad.get('SenderFault')!r}"
    )
    assert bad.get("Message") == "The input receipt handle is invalid.", (
        f"Failed[{bad_id!r}].Message is {bad.get('Message')!r}"
    )

    # --- effect and effect-absent, read off the queue rather than the response -------------
    # Only the broken entry's message may come back. If any of the nine reappears, its
    # Successful entry did not really delete it; if NOTHING comes back, the Failed entry
    # deleted a message it reported it had refused.
    returned = _observe(sqs, url, timeout_s=redeliver_s)
    assert returned == [survivor], (
        f"after the visibility timeout lapsed the queue redelivered {returned}, expected "
        f"exactly [{survivor!r}] -- the nine Successful entries must be gone and the one "
        f"Failed entry's message must still be there"
    )
    assert not (set(returned) & deleted_bodies), (
        f"a message reported Successful came back: {sorted(set(returned) & deleted_bodies)}"
    )

    attrs = _poll(
        lambda: sqs.get_queue_attributes(
            QueueUrl=url,
            AttributeNames=["ApproximateNumberOfMessages",
                            "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"],
        lambda a: (a["ApproximateNumberOfMessages"] == "0"
                   and a["ApproximateNumberOfMessagesNotVisible"] == "0"),
        timeout_s=vis * 3,
    )
    assert attrs["ApproximateNumberOfMessages"] == "0", (
        f"queue still reports {attrs['ApproximateNumberOfMessages']!r} visible messages after "
        f"the survivor was drained"
    )
    assert attrs["ApproximateNumberOfMessagesNotVisible"] == "0", (
        f"queue still reports {attrs['ApproximateNumberOfMessagesNotVisible']!r} in flight "
        f"after every message was deleted"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
