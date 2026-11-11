"""get-queue-attributes-invalid-attribute-name."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-queue-attributes-invalid-attribute-name"
GROUP = 'errors'
SERVICES = ['sqs']

_UNKNOWN_ATTRIBUTE_MESSAGE = "Unknown Attribute BogusAttribute."


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetQueueAttributes rejects the unknown attribute name BogusAttribute with
    InvalidAttributeName and its exact message, while the same call for QueueArn returns
    it."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]
    assert "QueueArn" in attrs, f"positive control did not return QueueArn: {sorted(attrs)}"

    error = _client_error(
        lambda: sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["BogusAttribute"])
    )
    assert error.get("Code") == "InvalidAttributeName", (
        f"expected InvalidAttributeName, got {error.get('Code')!r}"
    )
    assert error.get("Message") == _UNKNOWN_ATTRIBUTE_MESSAGE, (
        f"expected message {_UNKNOWN_ATTRIBUTE_MESSAGE!r}, got {error.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
