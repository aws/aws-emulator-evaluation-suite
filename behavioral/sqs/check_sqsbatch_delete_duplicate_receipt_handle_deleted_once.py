"""sqsbatch-delete-duplicate-receipt-handle-deleted-once."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "sqsbatch-delete-duplicate-receipt-handle-deleted-once"
GROUP = 'state'
SERVICES = ['sqs']

ERR_RECEIPT_HANDLE_INVALID = "ReceiptHandleIsInvalid"

VISIBILITY_TIMEOUT_S = 5

_BOGUS_HANDLE = "AQEBsim2real-not-a-real-receipt-handle-1111111111"

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
    Deletes nothing -- the caller owns the handles."""
    handles = {}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and len(handles) < len(want):
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
        for msg in resp.get("Messages", []):
            handles.setdefault(msg["Body"], msg["ReceiptHandle"])
    return handles


def _observe(sqs, url, *, timeout_s):
    """Bodies of every distinct message that becomes visible inside timeout_s, each deleted so
    it is counted once. Always runs the full window: the window closing with nothing further
    arriving is the effect-absent evidence."""
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


# timing:real-time — visibility: 5 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """DeleteMessageBatch entries repeating one receipt handle under two Ids both succeed and delete
    it once; a bogus-handle entry fails alone with ReceiptHandleIsInvalid and an unnamed in-flight
    message redelivers untouched (entry uniqueness is by Id, not by receipt handle)."""
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
    # Outlasts one visibility timeout with room for the arrival itself. A poll for arrival,
    # never a claim about how fast it arrives.
    redeliver_s = vis * 2

    target, bystander = "dup-delete-target", "bystander-never-named"
    sent = sqs.send_message_batch(
        QueueUrl=url,
        Entries=[{"Id": "s0", "MessageBody": target}, {"Id": "s1", "MessageBody": bystander}],
    )
    assert not sent.get("Failed"), f"setup send batch failed: {sent.get('Failed')!r}"
    handles = _receive_by_body(sqs, url, want=[target, bystander], timeout_s=recv_s)
    assert set(handles) == {target, bystander}, (
        f"receive got {sorted(handles)} of {[target, bystander]} within {recv_s}s; both must be "
        f"in flight before the batch delete"
    )

    # One handle, two entry Ids, plus one bogus handle -- three entries, one call.
    resp = sqs.delete_message_batch(
        QueueUrl=url,
        Entries=[
            {"Id": "dup-a", "ReceiptHandle": handles[target]},
            {"Id": "dup-b", "ReceiptHandle": handles[target]},
            {"Id": "bogus", "ReceiptHandle": _BOGUS_HANDLE},
        ],
    )
    succ = {e["Id"] for e in resp.get("Successful", [])}
    fail = {e["Id"]: e for e in resp.get("Failed", [])}

    assert succ == {"dup-a", "dup-b"}, (
        f"Successful Ids {sorted(succ)}, expected both duplicate entries ['dup-a', 'dup-b']: "
        f"a redundant delete of an already-deleted message is idempotent, not a failure"
    )
    assert set(fail) == {"bogus"}, f"Failed Ids {sorted(fail)}, expected exactly ['bogus']"
    assert succ | set(fail) == {"dup-a", "dup-b", "bogus"}, (
        f"envelope Ids {sorted(succ | set(fail))} do not partition the three request Ids"
    )
    assert fail["bogus"].get("Code") == ERR_RECEIPT_HANDLE_INVALID, (
        f"Failed['bogus'].Code is {fail['bogus'].get('Code')!r}, expected "
        f"{ERR_RECEIPT_HANDLE_INVALID!r}"
    )
    assert fail["bogus"].get("Message") == "The input receipt handle is invalid.", (
        f"Failed['bogus'].Message is {fail['bogus'].get('Message')!r}"
    )
    assert fail["bogus"].get("SenderFault") is True, (
        f"Failed['bogus'].SenderFault is {fail['bogus'].get('SenderFault')!r}, expected True"
    )

    # Effect and blast radius, read off the queue: the target is gone for good (one delete, not
    # two), and the bystander -- in flight, named by no entry -- comes back untouched.
    returned = _observe(sqs, url, timeout_s=redeliver_s)
    assert returned == [bystander], (
        f"after the visibility timeout lapsed the queue redelivered {returned}, expected "
        f"exactly [{bystander!r}]: {target!r} coming back would mean neither Successful entry "
        f"deleted it, and an empty result would mean the batch consumed the bystander too"
    )

    attrs = _poll(
        lambda: sqs.get_queue_attributes(
            QueueUrl=url,
            AttributeNames=["ApproximateNumberOfMessages",
                            "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"],
        lambda a: (a["ApproximateNumberOfMessages"] == "0"
                   and a["ApproximateNumberOfMessagesNotVisible"] == "0"),
        timeout_s=vis * 2,
    )
    assert attrs["ApproximateNumberOfMessages"] == "0", (
        f"queue still reports {attrs['ApproximateNumberOfMessages']!r} visible messages"
    )
    assert attrs["ApproximateNumberOfMessagesNotVisible"] == "0", (
        f"queue still reports {attrs['ApproximateNumberOfMessagesNotVisible']!r} in flight"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
