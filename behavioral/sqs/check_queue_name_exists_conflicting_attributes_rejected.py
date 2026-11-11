"""queue-name-exists-conflicting-attributes-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "queue-name-exists-conflicting-attributes-rejected"
GROUP = "overly-permissive"
SERVICES = ["sqs"]

# Exact messages real SQS returns for these refusals.
MSG_EXISTS = 'A queue already exists with the same name and a different value for attribute ContentBasedDeduplication'


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateQueue reusing an existing FIFO queue's name with a different ContentBasedDeduplication is
    rejected with QueueAlreadyExists and its exact message and leaves the attribute unchanged,
    while the same call with identical attributes returns the same URL."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-sqs-fifonameconflict-") + ".fifo"
    url = sqs.create_queue(
        QueueName=name,
        Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    # Positive control: the FIFO-specific attribute actually took effect on creation.
    created_attrs = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["ContentBasedDeduplication"]
    )["Attributes"]
    assert created_attrs["ContentBasedDeduplication"] == "true", (
        f"expected ContentBasedDeduplication=true right after creation, got {created_attrs!r}"
    )

    err = _client_error(
        lambda: sqs.create_queue(
            QueueName=name,
            Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "false"},
        )
    )
    # Real AWS returns the wire error code "QueueAlreadyExists" for this condition (the
    # Smithy/API-doc shape name "QueueNameExists" is not the wire code).
    assert err.get("Code") == "QueueAlreadyExists", f"expected QueueAlreadyExists, got {err!r}"
    assert err.get("Message") == MSG_EXISTS, f"got {err!r}"

    # the conflicting call must not have mutated the existing queue's FIFO-specific attribute
    attrs = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["ContentBasedDeduplication"]
    )["Attributes"]
    assert attrs["ContentBasedDeduplication"] == "true", (
        f"ContentBasedDeduplication changed to {attrs['ContentBasedDeduplication']!r} "
        "by a rejected CreateQueue call"
    )

    # positive control: identical attributes -> idempotent success, same URL returned
    idempotent = sqs.create_queue(
        QueueName=name,
        Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true"},
    )
    assert idempotent["QueueUrl"] == url, (
        f"expected identical re-create to return the same queue URL {url!r}, got {idempotent['QueueUrl']!r}"
    )

    # Terminal independent read: the idempotent re-create did not change the attribute either.
    final_attrs = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["ContentBasedDeduplication"]
    )["Attributes"]
    assert final_attrs["ContentBasedDeduplication"] == "true", (
        f"ContentBasedDeduplication changed to {final_attrs['ContentBasedDeduplication']!r} "
        "after an idempotent re-create"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected rejection but call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
