"""binary-message-attribute."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "binary-message-attribute"
GROUP = 'invariants'
SERVICES = ['sqs']

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Binary MessageAttribute (DataType=Binary) round-trips byte-exact."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"),
        tags={"sim2real-check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    payload = bytes(range(256))
    sent = {"blob": {"DataType": "Binary", "BinaryValue": payload}}
    sqs.send_message(QueueUrl=url, MessageBody="binary-attr", MessageAttributes=sent)
    received = []
    _seen = set()
    _idle = 0
    for _ in range(12):
        _resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=1, MessageAttributeNames=["All"])
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
            sqs.delete_message(QueueUrl=url, ReceiptHandle=_m["ReceiptHandle"])
        if len(received) >= 1:
            break
    assert received, "no message received"
    got = received[0].get("MessageAttributes", {}).get("blob")
    assert got, "binary attribute missing on receive"
    assert got.get("DataType") == "Binary", f"DataType mismatch: {got.get('DataType')!r}"
    assert got.get("BinaryValue") == payload, "BinaryValue did not round-trip byte-exact"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
