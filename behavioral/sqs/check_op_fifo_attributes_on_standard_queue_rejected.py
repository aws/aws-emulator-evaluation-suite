"""op-fifo-attributes-on-standard-queue-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-fifo-attributes-on-standard-queue-rejected"
GROUP = 'errors'
SERVICES = ['sqs']

# Exact messages real SQS returns for these refusals.
MSG_CBD = 'Unknown Attribute ContentBasedDeduplication.'
MSG_FIFO = 'Unknown Attribute FifoQueue.'


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected rejection but call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """FIFO-only queue attributes must be rejected on a standard queue, and FifoQueue is immutable."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    err_cbd = _client_error(
        lambda: sqs.set_queue_attributes(QueueUrl=url, Attributes={"ContentBasedDeduplication": "true"})
    )
    assert err_cbd.get("Code") == "InvalidAttributeName", f"got {err_cbd!r}"
    assert err_cbd.get("Message") == MSG_CBD, f"got {err_cbd!r}"

    err_fifo = _client_error(
        lambda: sqs.set_queue_attributes(QueueUrl=url, Attributes={"FifoQueue": "true"})
    )
    assert err_fifo.get("Code") == "InvalidAttributeName", f"got {err_fifo!r}"
    assert err_fifo.get("Message") == MSG_FIFO, f"got {err_fifo!r}"

    attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"])["Attributes"]
    assert "FifoQueue" not in attrs, "standard queue was mutated into a FIFO queue"

    # Positive control: a genuinely writable attribute still succeeds on this same queue,
    # proving the two rejections above are specific to FIFO-only attributes and not a sign
    # that SetQueueAttributes is broken or denied outright for this queue.
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"VisibilityTimeout": "45"})
    control = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["VisibilityTimeout"])[
        "Attributes"
    ]["VisibilityTimeout"]
    assert control == "45", f"positive control failed: got {control}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
