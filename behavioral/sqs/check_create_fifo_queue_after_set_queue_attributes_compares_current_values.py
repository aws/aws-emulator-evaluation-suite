"""create-fifo-queue-after-set-queue-attributes-compares-current-values."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-fifo-queue-after-set-queue-attributes-compares-current-values"
GROUP = "overly-permissive"
SERVICES = ["sqs"]

_TAGS = {"sim2real": "create-fifo-queue-after-set-queue-attributes-compares-current-values"}
_PROPAGATION_DEADLINE_S = 90.0


def _err(fn):
    """(Code, Message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        e = exc.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll_attribute(sqs, url: str, attribute: str, want: str) -> str:
    """Poll GetQueueAttributes until ``attribute`` reads ``want``; SetQueueAttributes can take up
    to 60 s to propagate. Raises at the deadline."""
    deadline = time.monotonic() + _PROPAGATION_DEADLINE_S
    while True:
        got = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=[attribute])["Attributes"][
            attribute
        ]
        if got == want:
            return got
        if time.monotonic() > deadline:
            raise AssertionError(
                f"SetQueueAttributes did not take effect within {_PROPAGATION_DEADLINE_S}s: "
                f"{attribute} still reads {got!r}, expected {want!r}"
            )
        time.sleep(2.0)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateQueue on an existing FIFO queue's name compares ContentBasedDeduplication against
    the CURRENT value a later SetQueueAttributes set, not the creation-time one: a differing
    value is refused naming the current value; the current value resubmitted returns it.
    """
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-cqsqafifo-") + ".fifo"
    url = sqs.create_queue(
        QueueName=name,
        Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "false"},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    created_cbd = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["ContentBasedDeduplication"]
    )["Attributes"]["ContentBasedDeduplication"]
    assert created_cbd == "false", (
        f"positive control: ContentBasedDeduplication read back as {created_cbd!r}"
    )

    sqs.set_queue_attributes(QueueUrl=url, Attributes={"ContentBasedDeduplication": "true"})
    _poll_attribute(sqs, url, "ContentBasedDeduplication", "true")

    # CreateQueue with a value that differs from the CURRENT one (true), not the creation-time
    # one (false), is refused, and the refusal names the current value.
    code, message = _err(
        lambda: sqs.create_queue(
            QueueName=name,
            Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "false"},
        )
    )
    assert code == "QueueAlreadyExists", f"expected QueueAlreadyExists, got {code!r}"
    expected_message = (
        "A queue already exists with the same name and a different value for attribute "
        "ContentBasedDeduplication"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    cbd_after_conflict = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["ContentBasedDeduplication"]
    )["Attributes"]["ContentBasedDeduplication"]
    assert cbd_after_conflict == "true", (
        f"the refused CreateQueue changed ContentBasedDeduplication to {cbd_after_conflict!r}"
    )

    # CreateQueue with the CURRENT value (true) re-submitted, which differs from the
    # creation-time value (false), is accepted as the same queue.
    matched = sqs.create_queue(
        QueueName=name,
        Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true"},
    )["QueueUrl"]
    assert matched == url, (
        f"CreateQueue with the current ContentBasedDeduplication returned {matched!r}, "
        f"expected {url!r}"
    )
    cbd_final = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["ContentBasedDeduplication"]
    )["Attributes"]["ContentBasedDeduplication"]
    assert cbd_final == "true", (
        f"ContentBasedDeduplication read {cbd_final!r} after the matching re-create"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
