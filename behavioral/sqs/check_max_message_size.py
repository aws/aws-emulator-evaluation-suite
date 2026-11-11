"""max-message-size."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "max-message-size"
GROUP = 'errors'
SERVICES = ['sqs']

@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A 262144-byte message is accepted and round-trips byte-for-byte; a 2 MB message is rejected
    with HTTP 413 at the transport layer, before SQS field validation, and is not delivered."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    body_at_limit = "x" * (256 * 1024)
    sqs.send_message(QueueUrl=url, MessageBody=body_at_limit)
    _drained = []
    _seen = set()
    _idle = 0
    for _ in range(12):
        _resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=1)
        _msgs = _resp.get("Messages", [])
        if not _msgs:
            _idle += 1
            if _drained and _idle >= 3:
                break
            continue
        _idle = 0
        for _m in _msgs:
            if _m["MessageId"] not in _seen:
                _seen.add(_m["MessageId"])
                _drained.append(_m)
            sqs.delete_message(QueueUrl=url, ReceiptHandle=_m["ReceiptHandle"])
        if len(_drained) >= 1:
            break
    assert _drained, "message sent at the 262144-byte limit was never delivered"
    assert _drained[0]["Body"] == body_at_limit, (
        f"body at the size limit was altered in transit: len sent={len(body_at_limit)}, "
        f"len received={len(_drained[0]['Body'])}"
    )
    body_2mb = "x" * (2 * 1024 * 1024)
    try:
        sqs.send_message(QueueUrl=url, MessageBody=body_2mb)
        code = None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
    assert code == "413", f"expected a 413 (request entity too large) for a 2MB body, got {code}"
    _leftover = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get("Messages", [])
    assert _leftover == [], f"oversized body was rejected but still delivered: {_leftover}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
