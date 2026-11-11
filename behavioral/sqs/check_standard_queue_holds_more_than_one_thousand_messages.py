"""standard-queue-holds-more-than-one-thousand-messages."""

from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "standard-queue-holds-more-than-one-thousand-messages"
GROUP = "limits"
SERVICES = ["sqs"]

_COUNT = 1001
_COUNTER_CAP_S = 120.0
_DRAIN_CAP_S = 120.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The poll then fails with its own message.
    """
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A standard queue holds 1,001 messages: every batch entry succeeds and every body is received.

    ApproximateNumberOfMessages reaches 1001 before any receive.
    """
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-volq-")
    ctx.on_cleanup(lambda: _drop_queue(sqs, name))
    url = sqs.create_queue(QueueName=name, Attributes={"VisibilityTimeout": "300"})["QueueUrl"]

    bodies = [f"m-{i:04d}" for i in range(_COUNT)]
    message_ids = set()
    for base in range(0, _COUNT, 10):
        chunk = bodies[base : base + 10]
        out = sqs.send_message_batch(
            QueueUrl=url, Entries=[{"Id": f"e{j}", "MessageBody": b} for j, b in enumerate(chunk)]
        )
        assert not out.get("Failed"), f"batch at {base} reported failures {out.get('Failed')!r}"
        assert len(out.get("Successful") or []) == len(chunk), (
            f"batch at {base} acknowledged {len(out.get('Successful') or [])} of {len(chunk)}"
        )
        message_ids.update(e["MessageId"] for e in out["Successful"])
    assert len(message_ids) == _COUNT, (
        f"{_COUNT} sends must return distinct MessageIds; got {len(message_ids)}"
    )

    count = None
    deadline = time.monotonic() + _budget_s(ctx, _COUNTER_CAP_S)
    while time.monotonic() < deadline:
        count = sqs.get_queue_attributes(
            QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"]
        )["Attributes"]["ApproximateNumberOfMessages"]
        if int(count) >= _COUNT:
            break
        time.sleep(2)
    else:
        if _budget_spent(ctx):
            raise TimeoutError(
                "waiting for ApproximateNumberOfMessages: the run budget ended first; not graded"
            )
        raise AssertionError(
            f"ApproximateNumberOfMessages never reached {_COUNT}; last read {count!r}"
        )

    received = set()
    deadline = time.monotonic() + _budget_s(ctx, _DRAIN_CAP_S)
    while len(received) < _COUNT and time.monotonic() < deadline:
        out = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
        msgs = out.get("Messages") or []
        received.update(m["Body"] for m in msgs)
    if len(received) < _COUNT and _budget_spent(ctx):
        raise TimeoutError("receiving every message: the run budget ended first; not graded")
    assert received == set(bodies), (
        f"the queue must deliver all {_COUNT} bodies; {len(set(bodies) - received)} never arrived, "
        f"e.g. {sorted(set(bodies) - received)[:3]!r}"
    )


def _drop_queue(sqs, name: str) -> None:
    """The cleanup: delete the queue by name. A queue never made is fine."""
    try:
        url = sqs.get_queue_url(QueueName=name)["QueueUrl"]
    except sqs.exceptions.QueueDoesNotExist:
        return
    sqs.delete_queue(QueueUrl=url)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
