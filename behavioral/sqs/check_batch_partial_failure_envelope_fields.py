"""batch-partial-failure-envelope-fields."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-partial-failure-envelope-fields"
GROUP = 'errors'
SERVICES = ['sqs']

ERR_EMPTY_VALUE = "EmptyValue"


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

    Runs the full window on purpose: the window elapsing with nothing further
    arriving is the evidence that a rejected entry did NOT enqueue.
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


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendMessageBatch with an empty-body entry between two valid ones echoes the request Ids
    and fails only that entry with EmptyValue, SenderFault=True and "No Value Found for
    SendMessageBatchRequestEntry.2.MessageBody."; exactly the two valid bodies enqueue."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    drain_s = 12

    control = sqs.send_message_batch(
        QueueUrl=url,
        Entries=[
            {"Id": "ctl-a", "MessageBody": "control-a"},
            {"Id": "ctl-b", "MessageBody": "control-b"},
        ],
    )
    ctl_ok = {e["Id"] for e in control.get("Successful", [])}
    assert ctl_ok == {"ctl-a", "ctl-b"}, f"control batch Successful Ids: {sorted(ctl_ok)}"
    assert not control.get("Failed"), f"control batch reported failures: {control.get('Failed')}"
    # A standard queue is unordered, so drained bodies are compared as a set.
    ctl_bodies = _drain(sqs, url, timeout_s=drain_s)
    assert set(ctl_bodies) == {"control-a", "control-b"}, f"control drain: {ctl_bodies}"

    entries = [
        {"Id": "valid-1", "MessageBody": "kept-body-1"},
        {"Id": "empty-2", "MessageBody": ""},
        {"Id": "valid-3", "MessageBody": "kept-body-3"},
    ]
    resp = sqs.send_message_batch(QueueUrl=url, Entries=entries)
    succ = {e["Id"]: e for e in resp.get("Successful", [])}
    fail = {e["Id"]: e for e in resp.get("Failed", [])}

    assert set(succ) == {"valid-1", "valid-3"}, f"Successful Ids: {sorted(succ)}"
    assert set(fail) == {"empty-2"}, f"Failed Ids: {sorted(fail)}"
    # Ids echo the request entry Ids exactly, not positional renumbering.
    assert set(succ) | set(fail) == {e["Id"] for e in entries}, (
        f"envelope Ids {sorted(set(succ) | set(fail))} do not match request Ids "
        f"{sorted(e['Id'] for e in entries)}"
    )

    bad = fail["empty-2"]
    assert bad.get("Code") == ERR_EMPTY_VALUE, f"Failed Code: {bad.get('Code')!r}"
    assert bad.get("SenderFault") is True, (
        f"Failed SenderFault must be True for a client error, got {bad.get('SenderFault')!r}"
    )
    expected = "No Value Found for SendMessageBatchRequestEntry.2.MessageBody."
    assert bad.get("Message") == expected, f"Failed Message: expected {expected!r}, got {bad.get('Message')!r}"
    for eid, entry in succ.items():
        assert entry.get("MessageId"), f"{eid} Successful entry has no MessageId"
        md5 = entry.get("MD5OfMessageBody") or ""
        assert len(md5) == 32, f"{eid} MD5OfMessageBody is not a 32-char digest: {md5!r}"

    bodies = _drain(sqs, url, timeout_s=drain_s)
    assert set(bodies) == {"kept-body-1", "kept-body-3"}, (
        f"expected exactly the two valid bodies to be enqueued, drained {bodies}"
    )
    remaining = _poll(
        lambda: sqs.get_queue_attributes(
            QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"]
        )["Attributes"]["ApproximateNumberOfMessages"],
        lambda v: v == "0",
        timeout_s=30,
    )
    assert remaining == "0", f"queue still reports {remaining} messages after draining both"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
