"""delete-message-batch-partial-failure."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-message-batch-partial-failure"
GROUP = 'errors'
SERVICES = ['sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": CHECK}


def _receive_messages(sqs, url, *, min_count, max_batch=10, attempts=15):
    received = []
    _seen = set()
    _idle = 0
    for _ in range(attempts):
        _resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=max_batch, WaitTimeSeconds=1)
        _msgs = _resp.get("Messages", [])
        if not _msgs:
            _idle += 1
            if received and _idle >= 3:
                break
            continue
        _idle = 0
        for _m in _msgs:
            if _m["MessageId"] not in _seen:
                _seen.add(_m["MessageId"])
                received.append(_m)
        if len(received) >= min_count:
            break
    return received


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteMessageBatch is per-entry: a cross-queue receipt handle fails with
    ReceiptHandleIsInvalid while the valid one succeeds; both queues are re-read to confirm.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"),
        Attributes={"VisibilityTimeout": "2"},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    other_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"),
        Attributes={"VisibilityTimeout": "2"},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=other_url))

    sqs.send_message(QueueUrl=url, MessageBody="m1")
    sqs.send_message(QueueUrl=url, MessageBody="m2")
    msgs = _receive_messages(sqs, url, min_count=2, attempts=20)
    assert len(msgs) >= 2, f"expected 2 messages, got {len(msgs)}"
    id1, id2 = msgs[0]["MessageId"], msgs[1]["MessageId"]
    handle1, handle2 = msgs[0]["ReceiptHandle"], msgs[1]["ReceiptHandle"]

    sqs.send_message(QueueUrl=other_url, MessageBody="other")
    other_msgs = _receive_messages(sqs, other_url, min_count=1, max_batch=1, attempts=20)
    assert other_msgs, "other-queue message never became visible"
    other_id = other_msgs[0]["MessageId"]
    other_handle = other_msgs[0]["ReceiptHandle"]

    entries = [
        {"Id": "d1", "ReceiptHandle": handle1},
        {"Id": "d2", "ReceiptHandle": other_handle},
    ]
    resp = sqs.delete_message_batch(QueueUrl=url, Entries=entries)
    successful_ids = {s["Id"] for s in resp.get("Successful", [])}
    failed = {f["Id"]: f for f in resp.get("Failed", [])}

    assert successful_ids == {"d1"}, f"unexpected successes: {successful_ids}"
    assert "d2" in failed, f"cross-queue handle unexpectedly accepted: {resp}"
    assert failed["d2"]["Code"] == "ReceiptHandleIsInvalid", f"got {failed['d2']['Code']}"
    expected_message = f'The receipt handle "{other_handle}" is not valid for this queue.'
    assert failed["d2"].get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {failed['d2'].get('Message')!r}"
    )

    # Independent read at the destination: wait out the 2s VisibilityTimeout on `url` and see what
    # actually redelivers. Only m2 (id2, never touched by the batch call) may reappear -- if m1
    # (id1) is also still there, the "Successful" d1 entry was a response-only claim.
    redelivered = _receive_messages(sqs, url, min_count=1, max_batch=10, attempts=20)
    redelivered_ids = {m["MessageId"] for m in redelivered}
    assert redelivered_ids == {id2}, (
        f"expected only m2 ({id2}) to redeliver from {url!r} after the batch delete, got "
        f"{redelivered_ids}; if {id1} reappeared the 'Successful' d1 entry did not really delete it"
    )
    fresh_handle2 = next(m["ReceiptHandle"] for m in redelivered if m["MessageId"] == id2)

    # Independent read at the destination the failed entry actually named: the "other" message must
    # still be sitting in other_url, unaffected by a batch call it was never truly part of.
    still_there = _receive_messages(sqs, other_url, min_count=1, max_batch=1, attempts=20)
    still_there_ids = {m["MessageId"] for m in still_there}
    assert still_there_ids == {other_id}, (
        f"expected the undeleted 'other' message ({other_id}) to still be in {other_url!r}, got "
        f"{still_there_ids}; a ReceiptHandleIsInvalid response that deleted the message anyway "
        f"would be worse than an outright acceptance"
    )
    fresh_other_handle = next(m["ReceiptHandle"] for m in still_there if m["MessageId"] == other_id)

    sqs.delete_message(QueueUrl=url, ReceiptHandle=fresh_handle2)
    sqs.delete_message(QueueUrl=other_url, ReceiptHandle=fresh_other_handle)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
