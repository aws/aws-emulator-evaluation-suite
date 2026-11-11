"""content-based-dedup-id-is-the-sha256-of-the-body."""
from __future__ import annotations

import hashlib
import time
import uuid

from behavioral_harness import tags

CHECK = "content-based-dedup-id-is-the-sha256-of-the-body"
GROUP = 'fifo'
SERVICES = ['sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": "cbd-sha256"}


def _sha256(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Content-based dedup ids are the lowercase hex SHA-256 of the body, sharing one id space with
    explicit ids: an equal explicit id collides in either order; the uppercase digest does not.
    """
    sqs = ctx.client("sqs")
    token = uuid.uuid4().hex[:8]
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + ".fifo",
        Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true"},
        tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    def send(body, dedup_id=None):
        kw = {"MessageDeduplicationId": dedup_id} if dedup_id else {}
        return sqs.send_message(QueueUrl=url, MessageBody=body, MessageGroupId="g",
                                **kw)["MessageId"]

    first = f"hashed-first-{token}"
    a = send(first)
    a_dup = send(f"explicit-collides-{token}", _sha256(first))
    assert a_dup == a, (
        f"an explicit MessageDeduplicationId equal to sha256(body) of a content-based send must "
        f"be deduplicated against it: first {a!r}, second {a_dup!r}")

    second = f"hashed-second-{token}"
    b = send(f"explicit-first-{token}", _sha256(second))
    b_dup = send(second)
    assert b_dup == b, (
        f"a content-based send whose body hashes to an already-used explicit id must be "
        f"deduplicated against it: explicit {b!r}, content-based {b_dup!r}")

    # Dedup ids are case-sensitive: the uppercase digest is a different id.
    third = f"hashed-third-{token}"
    c = send(f"explicit-upper-{token}", _sha256(third).upper())
    c_other = send(third)
    assert c_other != c, (
        f"deduplication ids are case-sensitive: the uppercase digest must not collide with the "
        f"content-based send, but both returned {c!r}")

    bodies: list[str] = []
    empties = 0
    deadline = time.monotonic() + 60
    while empties < 3 and time.monotonic() < deadline:
        batch = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                    WaitTimeSeconds=2).get("Messages", [])
        empties = 0 if batch else empties + 1
        for m in batch:
            bodies.append(m["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    want = [first, f"explicit-first-{token}", f"explicit-upper-{token}", third]
    assert bodies == want, (
        f"the queue must hold exactly the four non-duplicate sends in order: got {bodies!r}, "
        f"expected {want!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
