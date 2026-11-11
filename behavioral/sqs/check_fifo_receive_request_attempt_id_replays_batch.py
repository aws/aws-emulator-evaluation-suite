"""fifo-receive-request-attempt-id-replays-batch."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "fifo-receive-request-attempt-id-replays-batch"
GROUP = 'fifo'
SERVICES = ['sqs']


def _poll(fn, pred, *, timeout_s, interval_s=0.5):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A FIFO ReceiveMessage retried with the same ReceiveRequestAttemptId replays the same batch.

    A different attempt id gets nothing while the group's messages are still in flight.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + ".fifo",
        # Long enough that a re-receive under a new attempt id cannot succeed by timeout.
        Attributes={"FifoQueue": "true", "VisibilityTimeout": "30"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    token = uuid.uuid4().hex[:8]
    group = f"grp-{token}"
    bodies = [f"rraid-{i}-{token}" for i in range(3)]
    for i, body in enumerate(bodies):
        sqs.send_message(
            QueueUrl=url,
            MessageBody=body,
            MessageGroupId=group,
            MessageDeduplicationId=f"{token}-{i}",
        )

    attempt_1 = f"attempt-1-{token}"
    first = _poll(
        lambda: sqs.receive_message(
            QueueUrl=url,
            MaxNumberOfMessages=3,
            WaitTimeSeconds=2,
            ReceiveRequestAttemptId=attempt_1,
        ).get("Messages", []),
        lambda msgs: bool(msgs),
        timeout_s=30,
        interval_s=0,
    )
    assert first, "first ReceiveMessage returned nothing"
    first_ids = [m["MessageId"] for m in first]
    first_bodies = [m["Body"] for m in first]
    # Whatever prefix arrived, it must be a send-order prefix (asserted as a list).
    assert first_bodies == bodies[: len(first_bodies)], (
        f"first batch {first_bodies} is not a send-order prefix of {bodies}"
    )

    # MessageIds, not ReceiptHandles, are compared: the replay may carry fresh handles.
    replay = sqs.receive_message(
        QueueUrl=url,
        MaxNumberOfMessages=3,
        WaitTimeSeconds=2,
        ReceiveRequestAttemptId=attempt_1,
    ).get("Messages", [])
    replay_ids = [m["MessageId"] for m in replay]
    assert replay_ids == first_ids, (
        f"replay with the same ReceiveRequestAttemptId returned {replay_ids}, "
        f"expected the original batch {first_ids}"
    )
    assert [m["Body"] for m in replay] == first_bodies, (
        f"replay bodies {[m['Body'] for m in replay]} != {first_bodies}"
    )

    other = sqs.receive_message(
        QueueUrl=url,
        MaxNumberOfMessages=3,
        WaitTimeSeconds=2,
        ReceiveRequestAttemptId=f"attempt-2-{token}",
    ).get("Messages", [])
    assert other == [], (
        f"a new ReceiveRequestAttemptId handed out {[m['MessageId'] for m in other]} while "
        f"group {group} still had {len(first_ids)} message(s) in flight"
    )

    # Deleting with the latest response's handles releases the rest of the group.
    for msg in replay:
        sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    remaining = bodies[len(first_bodies):]
    if remaining:
        got = _poll(
            lambda: [
                m["Body"]
                for m in sqs.receive_message(
                    QueueUrl=url,
                    MaxNumberOfMessages=3,
                    WaitTimeSeconds=2,
                    ReceiveRequestAttemptId=f"attempt-3-{token}",
                ).get("Messages", [])
            ],
            lambda got: len(got) >= len(remaining),
            timeout_s=30,
            interval_s=0,
        )
        assert got == remaining, f"after the delete, expected {remaining} next, got {got}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
