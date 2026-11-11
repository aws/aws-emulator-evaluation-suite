"""message-attributes-roundtrip."""
from __future__ import annotations

import random

from behavioral_harness import tags

CHECK = "message-attributes-roundtrip"
GROUP = 'invariants'
SERVICES = ['sqs']

_SAFE_CHARS: tuple[str, ...] = tuple(
    [chr(c) for c in range(0x20, 0x7F)]
    + ["\t", "\n", "\r"]
    + list("áéíóúñüßçΩλµ§€—…")
    + list("日本語中文한국어")
    + ["😀", "🚀", "✅", "🌍"]
)

def _random_body(rng: random.Random, n_chars: int) -> str:
    return "".join(rng.choice(_SAFE_CHARS) for _ in range(n_chars))

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """String + Number MessageAttributes round-trip correctly."""
    sqs = ctx.client("sqs")
    rng = random.Random(0x5EED)
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"),
        tags={"sim2real-check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    string_value = _random_body(rng, 24).replace("\n", " ").replace("\r", " ").replace("\t", " ")
    number_value = str(rng.randint(0, 10_000_000))
    sent = {
        "flavour": {"DataType": "String", "StringValue": string_value},
        "priority": {"DataType": "Number", "StringValue": number_value},
    }
    sqs.send_message(QueueUrl=url, MessageBody="attrs-probe", MessageAttributes=sent)
    received = []
    _seen = set()
    _idle = 0
    for _ in range(12):
        _resp = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=1, MessageAttributeNames=["All"]
        )
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
    got = received[0].get("MessageAttributes")
    assert got, "no MessageAttributes on receive"
    for key, spec in sent.items():
        assert key in got, f"attribute {key!r} missing from received MessageAttributes {sorted(got)!r}"
        assert got[key].get("DataType") == spec["DataType"], (
            f"attribute {key!r} DataType mismatch: expected {spec['DataType']!r}, "
            f"got {got[key].get('DataType')!r}"
        )
        assert got[key].get("StringValue") == spec["StringValue"], (
            f"attribute {key!r} StringValue mismatch: expected {spec['StringValue']!r}, "
            f"got {got[key].get('StringValue')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
