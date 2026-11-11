"""list-dead-letter-source-queues-reflects-redrive-policy."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "list-dead-letter-source-queues-reflects-redrive-policy"
GROUP = "metadata"
SERVICES = ["sqs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDeadLetterSourceQueues on a DLQ returns exactly the source queues whose RedrivePolicy targets it."""
    sqs = ctx.client("sqs")
    dlq_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-dlq-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    src_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-src-"),
        Attributes={"RedrivePolicy": json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 5})},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=src_url))

    unrelated_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-unrelated-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=unrelated_url))

    other_dlq_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-otherdlq-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=other_dlq_url))
    other_dlq_arn = sqs.get_queue_attributes(QueueUrl=other_dlq_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    other_src_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-othersrc-"),
        Attributes={"RedrivePolicy": json.dumps({"deadLetterTargetArn": other_dlq_arn, "maxReceiveCount": 5})},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=other_src_url))

    result = sqs.list_dead_letter_source_queues(QueueUrl=dlq_url)
    urls = set(result.get("queueUrls", []))
    assert src_url in urls, f"source queue with matching RedrivePolicy missing from {urls}"
    assert unrelated_url not in urls, f"queue with no RedrivePolicy at all wrongly listed in {urls}"
    assert other_src_url not in urls, (
        f"queue whose RedrivePolicy targets a DIFFERENT dlq ({other_dlq_arn}) wrongly listed in {urls}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
