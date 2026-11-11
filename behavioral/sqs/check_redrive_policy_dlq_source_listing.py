"""redrive-policy-dlq-source-listing."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "redrive-policy-dlq-source-listing"
GROUP = 'visibility_dlq'
SERVICES = ['sqs']


def _poll(fn, pred, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A source queue with a RedrivePolicy pointing at a DLQ shows up in ListDeadLetterSourceQueues,
    an unrelated queue does not, and the source's own RedrivePolicy round-trips exactly."""
    sqs = ctx.client("sqs")
    dlq_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    redrive_policy = json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 3})
    src_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"), Attributes={"RedrivePolicy": redrive_policy}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=src_url))

    unrelated_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=unrelated_url))

    timeout_s = 180
    result = _poll(
        lambda: sqs.list_dead_letter_source_queues(QueueUrl=dlq_url).get("queueUrls", []),
        lambda urls: src_url in urls,
        timeout_s=timeout_s,
        interval_s=5,
    )
    assert src_url in result, f"source queue not listed in DLQ source queues: {result}"
    assert unrelated_url not in result, (
        f"queue with no RedrivePolicy targeting this DLQ was listed as a source: {result}"
    )

    attrs = sqs.get_queue_attributes(QueueUrl=src_url, AttributeNames=["RedrivePolicy"])["Attributes"]
    round_tripped = json.loads(attrs["RedrivePolicy"])
    assert round_tripped["deadLetterTargetArn"] == dlq_arn, (
        f"RedrivePolicy did not round-trip the DLQ arn: {round_tripped}"
    )
    assert round_tripped["maxReceiveCount"] == 3, f"RedrivePolicy did not round-trip maxReceiveCount: {round_tripped}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
