"""create-fifo-queue-without-suffix-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-fifo-queue-without-suffix-fails"
GROUP = 'errors'
SERVICES = ['sqs']


def _expect_aws_error(fn, *codes):
    """Call ``fn``, which AWS must refuse with one of ``codes``; return the ``ClientError``.

    A wrong code fails raised from the original error, so the failure keeps AWS's answer.
    """
    try:
        result = fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] in codes:
            return exc
        raise AssertionError(
            f"expected {' or '.join(codes)}, got {exc.response['Error']['Code']}"
        ) from exc
    raise AssertionError(f"expected {' or '.join(codes)}, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a FifoQueue=true queue whose name lacks the .fifo suffix must fail with the
    specific validation error, and the rejected name must never come into existence — while the
    identical account and API remain healthy for a properly-suffixed FIFO queue."""
    sqs = ctx.client("sqs")

    good_name = ctx.unique_name("sim2real-behav-fifobad-") + ".fifo"
    good_url = sqs.create_queue(QueueName=good_name, Attributes={"FifoQueue": "true"})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=good_url))
    assert good_url.endswith(".fifo"), f"positive control: expected .fifo URL, got {good_url!r}"

    bad_name = ctx.unique_name("sim2real-behav-fifobad-")  # deliberately missing ".fifo" suffix
    exc = _expect_aws_error(
        lambda: sqs.create_queue(QueueName=bad_name, Attributes={"FifoQueue": "true"}),
        "InvalidParameterValue",
    )
    expected_message = (
        "The name of a FIFO queue can only include alphanumeric characters, hyphens, or "
        "underscores, must end with .fifo suffix and be 1 to 80 in length."
    )
    message = exc.response["Error"].get("Message")
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The rejected name must never come into existence.
    exc = _expect_aws_error(
        lambda: sqs.get_queue_url(QueueName=bad_name), "AWS.SimpleQueueService.NonExistentQueue"
    )
    message = exc.response["Error"].get("Message")
    assert message == "The specified queue does not exist.", (
        f"expected message 'The specified queue does not exist.', got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
