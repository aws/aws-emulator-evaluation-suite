"""queue-attributes-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "queue-attributes-roundtrip"
GROUP = 'state'
SERVICES = ['sqs']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Create queue with custom attributes, verify via GetQueueAttributes."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"),
        Attributes={"VisibilityTimeout": "45", "MessageRetentionPeriod": "345600"},
        tags={"sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    attrs = sqs.get_queue_attributes(
        QueueUrl=url,
        AttributeNames=["VisibilityTimeout", "MessageRetentionPeriod"],
    )["Attributes"]
    assert attrs["VisibilityTimeout"] == "45", (
        f"VisibilityTimeout mismatch: {attrs['VisibilityTimeout']!r} != '45'"
    )
    assert attrs["MessageRetentionPeriod"] == "345600", (
        f"MessageRetentionPeriod mismatch: {attrs['MessageRetentionPeriod']!r} != '345600'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
