"""set-queue-attributes-roundtrip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "set-queue-attributes-roundtrip"
GROUP = 'state'
SERVICES = ['sqs']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetQueueAttributes AFTER create is reflected by GetQueueAttributes."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"), Attributes={"VisibilityTimeout": "30"})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    pre = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["VisibilityTimeout"])["Attributes"]
    assert pre.get("VisibilityTimeout") == "30", (
        f"positive control failed: expected VisibilityTimeout '30' right after create, got {pre.get('VisibilityTimeout')!r}"
    )

    sqs.set_queue_attributes(QueueUrl=url, Attributes={"VisibilityTimeout": "45"})
    # SetQueueAttributes changes can take up to 60s to propagate per AWS docs:
    # https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SetQueueAttributes.html
    deadline = time.monotonic() + 65.0
    attrs = {}
    while time.monotonic() < deadline:
        attrs = sqs.get_queue_attributes(
            QueueUrl=url, AttributeNames=["VisibilityTimeout"]
        )["Attributes"]
        if attrs.get("VisibilityTimeout") == "45":
            return
        time.sleep(2.0)
    raise AssertionError(
        f"VisibilityTimeout never reached 45 after SetQueueAttributes (last={attrs.get('VisibilityTimeout')!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
