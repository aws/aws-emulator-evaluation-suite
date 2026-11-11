"""change-message-visibility-batch-partial."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "change-message-visibility-batch-partial"
GROUP = 'errors'
SERVICES = ['sqs']


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
    """ChangeMessageVisibilityBatch applies per-entry: a valid handle succeeds while a bogus handle fails."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"),
        Attributes={"VisibilityTimeout": "5"},
        tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    sqs.send_message(QueueUrl=url, MessageBody="cmvb-1")
    msgs = _receive_messages(sqs, url, min_count=1, max_batch=1, attempts=20)
    assert msgs, "message never became visible"
    good_handle = msgs[0]["ReceiptHandle"]

    entries = [
        {"Id": "e1", "ReceiptHandle": good_handle, "VisibilityTimeout": 60},
        {"Id": "e2", "ReceiptHandle": "bogus-receipt-handle", "VisibilityTimeout": 60},
    ]
    resp = sqs.change_message_visibility_batch(QueueUrl=url, Entries=entries)
    successful = {s["Id"] for s in resp.get("Successful", [])}
    failed = {f["Id"]: f for f in resp.get("Failed", [])}

    assert successful == {"e1"}, f"unexpected successes: {successful}"
    assert "e2" in failed, f"bogus handle unexpectedly accepted: {resp}"
    assert failed["e2"]["Code"] == "ReceiptHandleIsInvalid", f"got {failed['e2']['Code']}"
    assert failed["e2"].get("Message") == "The input receipt handle is invalid.", (
        f"got message {failed['e2'].get('Message')!r}"
    )

    # entry e1's extension must actually take effect: message stays hidden
    hidden = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=3).get("Messages", [])
    assert hidden == [], "message became visible despite batch visibility extension"

    sqs.change_message_visibility(QueueUrl=url, ReceiptHandle=good_handle, VisibilityTimeout=0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
