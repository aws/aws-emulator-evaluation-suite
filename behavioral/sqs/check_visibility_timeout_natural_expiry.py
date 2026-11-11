"""visibility-timeout-natural-expiry."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "visibility-timeout-natural-expiry"
GROUP = 'visibility_dlq'
SERVICES = ['sqs']

@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A received message is hidden immediately, then becomes visible again once its 2-second
    visibility timeout lapses on its own, with no ChangeMessageVisibility call."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"),
        Attributes={"VisibilityTimeout": "2"},
        tags={"sim2real-check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    body = f"vt-expiry-{uuid.uuid4().hex[:8]}"
    sqs.send_message(QueueUrl=url, MessageBody=body)
    first = []
    _seen = set()
    _idle = 0
    for _ in range(12):
        _resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=1)
        _msgs = _resp.get("Messages", [])
        if not _msgs:
            _idle += 1
            if first and _idle >= 3:
                break
            continue
        _idle = 0
        for _m in _msgs:
            if _m["MessageId"] not in _seen:
                _seen.add(_m["MessageId"])
                first.append(_m)
        if len(first) >= 1:
            break
    assert first, "no message received"
    # Immediately hidden while in-flight.
    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=0)
    assert not resp.get("Messages"), "message still visible immediately after receive (VT not applied)"
    # After the 2s VT lapses it must be receivable again — WITHOUT any CMV call. No fixed sleep:
    # the retry loop below is the bounded wait, long-polling past the VT deadline.
    again = []
    _seen = set()
    _idle = 0
    for _ in range(5):
        _resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=1)
        _msgs = _resp.get("Messages", [])
        if not _msgs:
            _idle += 1
            if again and _idle >= 3:
                break
            continue
        _idle = 0
        for _m in _msgs:
            if _m["MessageId"] not in _seen:
                _seen.add(_m["MessageId"])
                again.append(_m)
        if len(again) >= 1:
            break
    assert again, "message never re-appeared after visibility timeout lapsed"
    assert again[0]["MessageId"] == first[0]["MessageId"], "different message after visibility timeout expiry"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
