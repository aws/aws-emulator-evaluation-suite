"""set-queue-attributes-readonly-attribute-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-queue-attributes-readonly-attribute-rejected"
GROUP = "error-semantics"
SERVICES = ["sqs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetQueueAttributes rejects writes to a read-only attribute (ApproximateNumberOfMessages)
    instead of silently accepting/ignoring it, while a real mutable attribute still persists."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-roattr-"),
        tags={"sim2real-check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    before = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]["ApproximateNumberOfMessages"]

    code, message = _error(
        lambda: sqs.set_queue_attributes(
            QueueUrl=url, Attributes={"ApproximateNumberOfMessages": "1234"}
        )
    )
    assert code == "InvalidAttributeName", (
        f"expected InvalidAttributeName rejecting a write to the read-only "
        f"ApproximateNumberOfMessages attribute, got {code!r}"
    )
    assert message == "Unknown Attribute ApproximateNumberOfMessages.", (
        f"unexpected refusal message {message!r}"
    )

    # effect absent: the read-only attribute did not take on the rejected value
    after = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]["ApproximateNumberOfMessages"]
    assert after != "1234", f"rejected write still took effect: ApproximateNumberOfMessages={after!r}"
    assert after == before, f"expected ApproximateNumberOfMessages to stay {before!r}, got {after!r}"

    # positive control: a genuinely mutable attribute is accepted and persisted
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"VisibilityTimeout": "45"})
    control = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["VisibilityTimeout"])[
        "Attributes"
    ]["VisibilityTimeout"]
    assert control == "45", f"expected VisibilityTimeout='45' after a genuinely mutable set, got {control!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
