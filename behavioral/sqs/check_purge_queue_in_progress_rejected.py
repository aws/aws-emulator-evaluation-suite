"""purge-queue-in-progress-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "purge-queue-in-progress-rejected"
GROUP = "overly-permissive"
SERVICES = ["sqs"]

PURGE_IN_PROGRESS = "AWS.SimpleQueueService.PurgeQueueInProgress"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A second PurgeQueue call within 60 seconds of a still-pending purge is rejected with
    PurgeQueueInProgress, while the first purge itself succeeds."""
    sqs = ctx.client("sqs")
    queue_name = ctx.unique_name("sim2real-sqs-purgeinprog-")
    url = sqs.create_queue(QueueName=queue_name)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    sqs.send_message(QueueUrl=url, MessageBody="to-be-purged")
    _poll_until(
        lambda: int(
            sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"])[
                "Attributes"
            ]["ApproximateNumberOfMessages"]
        ),
        lambda n: n >= 1,
        timeout_s=15.0,
    )

    sqs.purge_queue(QueueUrl=url)  # first purge: positive control -- succeeds

    # Real AWS returns the wire error code prefixed with the service namespace:
    # "AWS.SimpleQueueService.PurgeQueueInProgress". A message sent during the first
    # purge's window may or may not be deleted by that purge, so no message is graded here.
    code, message = _expect_rejected(lambda: sqs.purge_queue(QueueUrl=url))
    assert code == PURGE_IN_PROGRESS, f"expected {PURGE_IN_PROGRESS}, got {code!r}"
    assert message == f"Only one PurgeQueue operation on {queue_name} is allowed every 60 seconds.", (
        f"unexpected message: {message!r}"
    )


def _expect_rejected(fn):
    """Call fn(); return the ClientError (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        error = e.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
