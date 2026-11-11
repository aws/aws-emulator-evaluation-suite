"""receive-count-increments."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "receive-count-increments"
GROUP = 'visibility_dlq'
SERVICES = ['sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": "receive-count-increments"}

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ApproximateReceiveCount increments across receives (system attribute on receive)."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    sqs.send_message(QueueUrl=url, MessageBody="recv-count")
    first = sqs.receive_message(
        QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2, AttributeNames=["All"]
    ).get("Messages", [])
    if not first:
        raise AssertionError("no message received")
    attrs = first[0].get("Attributes", {})
    if attrs.get("ApproximateReceiveCount") != "1":
        raise AssertionError(
            f"expected ApproximateReceiveCount=1, got {attrs.get('ApproximateReceiveCount')!r}"
        )
    # Re-expose and receive again — count must advance to 2.
    sqs.change_message_visibility(
        QueueUrl=url, ReceiptHandle=first[0]["ReceiptHandle"], VisibilityTimeout=0
    )
    second = []
    _seen = set()
    _idle = 0
    for _ in range(12):
        _resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=1, AttributeNames=["All"])
        _msgs = _resp.get("Messages", [])
        if not _msgs:
            _idle += 1
            if second and _idle >= 3:
                break
            continue
        _idle = 0
        for _m in _msgs:
            if _m["MessageId"] not in _seen:
                _seen.add(_m["MessageId"])
                second.append(_m)
        if len(second) >= 1:
            break
    if not second:
        raise AssertionError("message not re-received")
    count = second[0].get("Attributes", {}).get("ApproximateReceiveCount")
    if count != "2":
        raise AssertionError(f"expected ApproximateReceiveCount=2 on second receive, got {count!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
