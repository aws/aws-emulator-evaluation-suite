"""queue-name-exists."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "queue-name-exists"
GROUP = 'errors'
SERVICES = ['sqs']

ERR_QUEUE_NAME_EXISTS = "QueueAlreadyExists"
_TAGS = {"sim2real:managed": "true", "sim2real": "queue-name-exists"}

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """create_queue re-using name with different attrs → QueueAlreadyExists, without
    mutating the existing queue; re-issuing create_queue with the SAME name and
    IDENTICAL attributes succeeds idempotently."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-")
    url = sqs.create_queue(QueueName=name, Attributes={"VisibilityTimeout": "30"}, tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    try:
        sqs.create_queue(QueueName=name, Attributes={"VisibilityTimeout": "60"})
        code = None
    except ClientError as exc:
        code = (exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message"))
    assert code == (
        ERR_QUEUE_NAME_EXISTS,
        "A queue already exists with the same name and a different value for attribute VisibilityTimeout",
    ), (
        f"expected {ERR_QUEUE_NAME_EXISTS}, got {code!r} "
        f"(None means conflicting create silently succeeded)"
    )

    # effect absent: the rejected conflicting create must not have mutated the queue
    attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["VisibilityTimeout"])["Attributes"]
    assert attrs["VisibilityTimeout"] == "30", (
        f"VisibilityTimeout changed to {attrs['VisibilityTimeout']!r} by a rejected create_queue call"
    )

    # restore beat: identical attributes → idempotent success, same URL returned
    idempotent = sqs.create_queue(QueueName=name, Attributes={"VisibilityTimeout": "30"})
    assert idempotent["QueueUrl"] == url, (
        f"identical create_queue should return the same URL, got {idempotent['QueueUrl']!r} vs {url!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
