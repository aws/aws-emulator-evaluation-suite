"""approximate-receive-count-increments."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "approximate-receive-count-increments"
GROUP = "lifecycle"
SERVICES = ["sqs"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ApproximateReceiveCount increments each time a message is redelivered after visibility expiry."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"),
        Attributes={"VisibilityTimeout": "2"},
        tags={"sim2real-check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    message_id = sqs.send_message(QueueUrl=url, MessageBody="track-my-receives")["MessageId"]

    first = _poll_until(
        lambda: sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=5, AttributeNames=["ApproximateReceiveCount"]
        ).get("Messages", []),
        lambda msgs: len(msgs) == 1,
        timeout_s=20.0,
    )[0]
    assert first["MessageId"] == message_id, f"expected first receive to return {message_id!r}, got {first['MessageId']!r}"
    assert first["Attributes"]["ApproximateReceiveCount"] == "1", (
        f"expected ApproximateReceiveCount=1 on first receive, got "
        f"{first['Attributes']['ApproximateReceiveCount']!r}"
    )

    second = _poll_until(
        lambda: sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=3, AttributeNames=["ApproximateReceiveCount"]
        ).get("Messages", []),
        lambda msgs: any(m["MessageId"] == message_id for m in msgs),
        timeout_s=20.0,
    )
    reborn = next(m for m in second if m["MessageId"] == message_id)
    assert reborn["Attributes"]["ApproximateReceiveCount"] == "2", (
        f"expected ApproximateReceiveCount=2 after redelivery past the 2s VisibilityTimeout, got "
        f"{reborn['Attributes']['ApproximateReceiveCount']!r}"
    )
    sqs.delete_message(QueueUrl=url, ReceiptHandle=reborn["ReceiptHandle"])


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
