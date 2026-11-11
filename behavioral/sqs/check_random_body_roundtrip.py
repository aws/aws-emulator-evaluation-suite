"""random-body-roundtrip."""
from __future__ import annotations

import hashlib
import random
import uuid

from behavioral_harness import tags

CHECK = "random-body-roundtrip"
GROUP = 'invariants'
SERVICES = ['sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": CHECK}

_SAFE_CHARS: tuple[str, ...] = tuple(
    [chr(c) for c in range(0x20, 0x7F)]
    + ["\t", "\n", "\r"]
    + list("áéíóúñüßçΩλµ§€—…")
    + list("日本語中文한국어")
    + ["😀", "🚀", "✅", "🌍"]
)

def _md5_hex(body: str) -> str:
    return hashlib.md5(body.encode("utf-8")).hexdigest()

def _random_body(rng: random.Random, n_chars: int) -> str:
    return "".join(rng.choice(_SAFE_CHARS) for _ in range(n_chars))

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Random bodies (varied size + charset) round-trip byte-exact with correct MD5."""
    sqs = ctx.client("sqs")
    rng = random.Random(0xB0D8)
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    token = uuid.uuid4().hex[:8]
    bodies = {
        f"{i}|{token}|{_random_body(rng, size)}"
        for i, size in enumerate((1, 20, 500, 5_000, 60_000))
    }
    md5s = {body: _md5_hex(body) for body in bodies}
    for body in bodies:
        sqs.send_message(QueueUrl=url, MessageBody=body)
    received = []
    _seen = set()
    _idle = 0
    for _ in range(20):
        _resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
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
        if len(received) >= len(bodies):
            break
    got = {m["Body"] for m in received}
    assert got == bodies, f"body set mismatch: sent {len(bodies)}, got {len(got)} distinct"
    for msg in received:
        expected = md5s[msg["Body"]]
        assert msg["MD5OfBody"] == expected, f"MD5OfBody mismatch: {msg['MD5OfBody']} != {expected}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
