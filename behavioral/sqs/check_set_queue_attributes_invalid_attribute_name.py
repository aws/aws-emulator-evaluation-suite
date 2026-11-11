"""set-queue-attributes-invalid-attribute-name."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-queue-attributes-invalid-attribute-name"
GROUP = 'errors'
SERVICES = ['sqs']


def _err(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected SetQueueAttributes to reject NotARealAttribute, but it succeeded: {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetQueueAttributes rejects an attribute key that SQS does not recognize, while a
    genuinely mutable attribute on the same queue is still accepted and persisted."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    code, message = _err(
        lambda: sqs.set_queue_attributes(QueueUrl=url, Attributes={"NotARealAttribute": "x"})
    )
    assert code == "InvalidAttributeName", f"expected InvalidAttributeName, got {code}"
    assert message == "Unknown Attribute NotARealAttribute.", f"unexpected message {message!r}"

    # positive control: a genuinely mutable attribute on the same queue is accepted and
    # persisted, so the rejection above is specific to the bogus key, not a broken queue
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"VisibilityTimeout": "45"})
    control = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["VisibilityTimeout"])[
        "Attributes"
    ]["VisibilityTimeout"]
    assert control == "45", f"expected VisibilityTimeout to persist as '45', got {control!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
