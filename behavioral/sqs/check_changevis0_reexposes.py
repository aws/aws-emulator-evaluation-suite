"""changevis0-reexposes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "changevis0-reexposes"
GROUP = 'visibility_dlq'
SERVICES = ['sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": "changevis0-reexposes"}

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ChangeMessageVisibility(0) makes an in-flight message immediately receivable."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    sqs.send_message(QueueUrl=url, MessageBody="changevis0")
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
    if not first:
        raise AssertionError("no message received")
    sqs.change_message_visibility(
        QueueUrl=url, ReceiptHandle=first[0]["ReceiptHandle"], VisibilityTimeout=0
    )
    again = []
    _seen = set()
    _idle = 0
    for _ in range(12):
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
    if not again:
        raise AssertionError("message not re-exposed after VT=0")
    if again[0]["MessageId"] != first[0]["MessageId"]:
        raise AssertionError("different message after re-expose")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
