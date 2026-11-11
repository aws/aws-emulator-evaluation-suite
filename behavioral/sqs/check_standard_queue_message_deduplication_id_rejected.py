"""standard-queue-message-deduplication-id-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "standard-queue-message-deduplication-id-rejected"
GROUP = "fair-queues"
SERVICES = ["sqs"]

_DEDUP_ID = "order-42"
_DEDUP_MESSAGE = (
    f"Value {_DEDUP_ID} for parameter MessageDeduplicationId is invalid. Reason: The request "
    f"include parameter that is not valid for this queue type."
)


def _error(fn) -> dict:
    """The botocore Error dict ``fn`` raises. An unexpected success raises too, naming what came
    back: a standard queue that accepts a deduplication id must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """MessageDeduplicationId is refused on a standard queue, with or without MessageGroupId,
    and the refused sends enqueue nothing, while the same sends without it are delivered."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-stddedup-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    # Fair queues allow MessageGroupId on standard queues, but a standard queue never deduplicates.
    for label, extra in (
        ("dedup-only", {}),
        ("dedup-with-group", {"MessageGroupId": "tenant-a"}),
    ):
        err = _error(
            lambda extra=extra, label=label: sqs.send_message(
                QueueUrl=url, MessageBody=f"refused-{label}", MessageDeduplicationId=_DEDUP_ID,
                **extra,
            )
        )
        assert err.get("Code") == "InvalidParameterValue", (
            f"{label}: MessageDeduplicationId on a standard queue gave code {err.get('Code')!r}"
        )
        assert err.get("Message") == _DEDUP_MESSAGE, (
            f"{label}: expected message {_DEDUP_MESSAGE!r}, got {err.get('Message')!r}"
        )

    # positive controls: the same two sends without the deduplication id
    sqs.send_message(QueueUrl=url, MessageBody="accepted-plain")
    sqs.send_message(QueueUrl=url, MessageBody="accepted-grouped", MessageGroupId="tenant-a")

    bodies: list[str] = []
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get(
            "Messages", []
        )
        if not msgs and len(bodies) >= 2:
            break
        for m in msgs:
            bodies.append(m["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    assert sorted(bodies) == ["accepted-grouped", "accepted-plain"], (
        f"the queue must hold exactly the two accepted messages and neither refused one; "
        f"received {sorted(bodies)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
