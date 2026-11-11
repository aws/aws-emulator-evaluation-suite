"""visibility-timeout-out-of-range-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "visibility-timeout-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["sqs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetQueueAttributes rejects a VisibilityTimeout above the 43200s maximum; a valid value still applies."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"), Attributes={"VisibilityTimeout": "30"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    code, message = _error(
        lambda: sqs.set_queue_attributes(QueueUrl=url, Attributes={"VisibilityTimeout": "43201"})
    )
    assert code == "InvalidAttributeValue", f"expected InvalidAttributeValue, got {code!r}"
    expected_message = "Invalid value for the parameter VisibilityTimeout."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the attribute must remain at its original value.
    unchanged = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["VisibilityTimeout"])["Attributes"]
    assert unchanged["VisibilityTimeout"] == "30", (
        f"a rejected SetQueueAttributes must not change VisibilityTimeout, "
        f"but it is now {unchanged['VisibilityTimeout']!r}"
    )

    # Positive control: a value within range is accepted and eventually observable (propagation
    # can take up to 60s per AWS docs) -- poll for it rather than asserting immediately.
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"VisibilityTimeout": "45"})
    _poll_until(
        lambda: sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["VisibilityTimeout"])["Attributes"][
            "VisibilityTimeout"
        ],
        lambda v: v == "45",
        timeout_s=65.0,
        interval_s=3.0,
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected SetQueueAttributes to reject VisibilityTimeout=43201, but it succeeded: {result!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
