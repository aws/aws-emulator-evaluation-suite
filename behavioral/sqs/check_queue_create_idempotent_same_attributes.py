"""queue-create-idempotent-same-attributes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "queue-create-idempotent-same-attributes"
GROUP = 'state'
SERVICES = ['sqs']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateQueue repeated with identical name and attributes returns the same URL, creates no
    second queue, and persists the requested attributes, per independent GetQueueUrl and
    GetQueueAttributes reads."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-")
    attrs = {"VisibilityTimeout": "60", "MessageRetentionPeriod": "3600"}

    url1 = sqs.create_queue(QueueName=name, Attributes=attrs)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url1))

    url2 = sqs.create_queue(QueueName=name, Attributes=attrs)["QueueUrl"]
    assert url1 == url2, f"idempotent CreateQueue must return the same QueueUrl, got {url1!r} vs {url2!r}"

    # independent read, through GetQueueUrl (never the mutating CreateQueue calls), proves
    # the second call did not spawn a second queue under the same name
    resolved = sqs.get_queue_url(QueueName=name)["QueueUrl"]
    assert resolved == url1, f"GetQueueUrl resolved to {resolved!r}, expected the created queue {url1!r}"

    # independent read of the persisted attributes: a target that ignores Attributes on
    # CreateQueue, or clobbers them on the idempotent re-create, must not pass this
    persisted = sqs.get_queue_attributes(
        QueueUrl=url1, AttributeNames=["VisibilityTimeout", "MessageRetentionPeriod"]
    )["Attributes"]
    assert persisted.get("VisibilityTimeout") == "60", (
        f"VisibilityTimeout expected '60', got {persisted.get('VisibilityTimeout')!r}"
    )
    assert persisted.get("MessageRetentionPeriod") == "3600", (
        f"MessageRetentionPeriod expected '3600', got {persisted.get('MessageRetentionPeriod')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
