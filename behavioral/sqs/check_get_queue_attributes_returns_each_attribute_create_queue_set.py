"""get-queue-attributes-returns-each-attribute-create-queue-set."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-queue-attributes-returns-each-attribute-create-queue-set"
GROUP = "representation"
SERVICES = ["sqs"]

_GONE = "AWS.SimpleQueueService.NonExistentQueue"
# Each value differs from the attribute's default, so a store that ignores it is caught.
_SENT = {
    "DelaySeconds": "5",
    "MaximumMessageSize": "2048",
    "MessageRetentionPeriod": "7200",
    "ReceiveMessageWaitTimeSeconds": "3",
    "VisibilityTimeout": "40",
}


def _drop_queue(sqs, url: str):
    """A cleanup deleting the queue; only the queue's own not-found code counts as already gone."""

    def undo() -> None:
        try:
            sqs.delete_queue(QueueUrl=url)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != _GONE:
                raise

    return undo


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetQueueAttributes returns every attribute CreateQueue set with the value sent, both when the
    attributes are named one by one and in the All listing.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-gqa-"), Attributes=dict(_SENT), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(_drop_queue(sqs, url))

    named = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=sorted(_SENT))["Attributes"]
    assert named == _SENT, f"the named read returned {named!r}, expected exactly {_SENT!r}"

    every = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"])["Attributes"]
    picked = {name: every.get(name) for name in _SENT}
    assert picked == _SENT, f"the All read carries {picked!r} for the sent attributes, expected {_SENT!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
