"""immutable-queue-arn-mutation-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "immutable-queue-arn-mutation-rejected"
GROUP = "invariants"
SERVICES = ["sqs"]

_READ_ONLY_ATTRIBUTE_MESSAGE = "Unknown Attribute QueueArn."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetQueueAttributes rejects setting the read-only QueueArn with InvalidAttributeName and its exact
    message and leaves the ARN unchanged, while a writable attribute set on the same queue succeeds."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-immarn-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    original_arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    error = _client_error(
        lambda: sqs.set_queue_attributes(
            QueueUrl=url,
            Attributes={"QueueArn": "arn:aws:sqs:us-east-1:123456789012:not-a-real-queue"},
        )
    )
    assert error.get("Code") == "InvalidAttributeName", (
        f"expected InvalidAttributeName, got {error.get('Code')!r}"
    )
    assert error.get("Message") == _READ_ONLY_ATTRIBUTE_MESSAGE, (
        f"expected message {_READ_ONLY_ATTRIBUTE_MESSAGE!r}, got {error.get('Message')!r}"
    )

    # Effect absent: the ARN did not change.
    unchanged_arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    assert unchanged_arn == original_arn, "QueueArn mutated despite rejected SetQueueAttributes"

    # Positive control: a genuinely writable attribute succeeds on the same queue.
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"VisibilityTimeout": "45"})
    vt = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["VisibilityTimeout"])[
        "Attributes"
    ]["VisibilityTimeout"]
    assert vt == "45", f"expected VisibilityTimeout '45', got {vt!r}"


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
