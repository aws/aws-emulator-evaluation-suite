"""long-poll-wakes-when-delay-or-visibility-expires."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "long-poll-wakes-when-delay-or-visibility-expires"
GROUP = "long-polling"
SERVICES = ["sqs"]

_DELAY_S = 4
_VISIBILITY_S = 4
_WAIT_S = 20


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A single long poll started while the only message is delayed, or in flight, returns it within
    the same call once the delay or visibility timeout expires (redelivery has a new handle)."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-lpwake-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    # Leg 1: delay expiry. Nothing else is on the queue, so the one call below can only return
    # this message, and only after its DelaySeconds has run out.
    sqs.send_message(QueueUrl=url, MessageBody="delayed", DelaySeconds=_DELAY_S)
    woke = sqs.receive_message(
        QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=_WAIT_S
    ).get("Messages", [])
    assert [m["Body"] for m in woke] == ["delayed"], (
        f"a {_WAIT_S}s long poll started inside a {_DELAY_S}s message delay must return the "
        f"message once the delay expires; it returned {[m['Body'] for m in woke]!r}"
    )
    sqs.delete_message(QueueUrl=url, ReceiptHandle=woke[0]["ReceiptHandle"])

    # Leg 2: visibility expiry. Receive the only message with a short visibility timeout, leave
    # it unacknowledged, and long-poll again while it is in flight.
    sqs.send_message(QueueUrl=url, MessageBody="in-flight")
    first = None
    deadline = time.monotonic() + 30
    while first is None and time.monotonic() < deadline:
        msgs = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2, VisibilityTimeout=_VISIBILITY_S
        ).get("Messages", [])
        first = msgs[0] if msgs else None
    assert first is not None and first["Body"] == "in-flight", (
        f"the second message was never delivered: {first!r}"
    )
    again = sqs.receive_message(
        QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=_WAIT_S,
        MessageSystemAttributeNames=["ApproximateReceiveCount"],
    ).get("Messages", [])
    assert [m["Body"] for m in again] == ["in-flight"], (
        f"a {_WAIT_S}s long poll started while the only message was in flight for "
        f"{_VISIBILITY_S}s must return it once the visibility timeout expires; it returned "
        f"{[m['Body'] for m in again]!r}"
    )
    count = again[0]["Attributes"].get("ApproximateReceiveCount")
    assert count == "2", f"the redelivery must be the message's second receive; count was {count!r}"
    assert again[0]["ReceiptHandle"] != first["ReceiptHandle"], (
        "the redelivery inside the long poll must carry a new receipt handle"
    )
    sqs.delete_message(QueueUrl=url, ReceiptHandle=again[0]["ReceiptHandle"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
