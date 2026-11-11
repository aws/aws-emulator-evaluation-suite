"""set-queue-attributes-propagates-to-get-queue-attributes."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "set-queue-attributes-propagates-to-get-queue-attributes"
GROUP = "state"
SERVICES = ["sqs"]

_TAGS = {"sim2real:managed": "true", "sim2real": "set-queue-attributes-propagates"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetQueueAttributes changes are observable via GetQueueAttributes; propagation is
    documented as eventually consistent (up to ~60s) so we poll rather than assert
    instantly."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-sqs-setattr-"),
        Attributes={"VisibilityTimeout": "30"},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["VisibilityTimeout"])["Attributes"]
    assert attrs["VisibilityTimeout"] == "30", (
        f"expected initial VisibilityTimeout '30', got {attrs['VisibilityTimeout']!r}"
    )

    sqs.set_queue_attributes(QueueUrl=url, Attributes={"VisibilityTimeout": "45"})

    # https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SetQueueAttributes.html
    # "the change can take up to 60 seconds for most attributes to propagate"
    _poll_until(
        lambda: sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["VisibilityTimeout"])[
            "Attributes"
        ]["VisibilityTimeout"],
        lambda v: v == "45",
        timeout_s=65.0,
    )


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=2.0):
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
