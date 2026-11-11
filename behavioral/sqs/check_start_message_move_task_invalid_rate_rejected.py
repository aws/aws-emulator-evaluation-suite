"""start-message-move-task-invalid-rate-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-message-move-task-invalid-rate-rejected"
GROUP = "error-semantics"
SERVICES = ["sqs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartMessageMoveTask with MaxNumberOfMessagesPerSecond above the documented 500
    cap is rejected before any move task is created, while a valid rate does create one."""
    sqs = ctx.client("sqs")

    dlq_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-mmtdlq-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    src_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-mmtsrc-"),
        Attributes={
            "RedrivePolicy": json.dumps(
                {"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 1}
            )
        },
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=src_url))

    # wait for the DLQ association to register (SQS attribute propagation, up to ~60s:
    # https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html)
    _poll_until(
        lambda: src_url in sqs.list_dead_letter_source_queues(QueueUrl=dlq_url).get(
            "queueUrls", []
        ),
        timeout_s=90,
        interval_s=3,
    )

    code, message = _error(
        lambda: sqs.start_message_move_task(
            SourceArn=dlq_arn, MaxNumberOfMessagesPerSecond=501
        )
    )
    assert code == "InvalidParameterValue", (
        f"expected InvalidParameterValue for MaxNumberOfMessagesPerSecond=501, got {code!r}"
    )
    assert message == (
        "Value for parameter MaxNumberOfMessagesPerSecond is invalid. "
        "Reason: You must enter a number that's between 1 and 500."
    ), f"unexpected refusal message {message!r}"

    # effect absent: no move task was created by the rejected call
    tasks_after_reject = sqs.list_message_move_tasks(SourceArn=dlq_arn).get("Results", [])
    assert tasks_after_reject == [], (
        f"the rejected call left move task(s) behind: {tasks_after_reject!r}"
    )

    # positive control: an in-range rate is accepted and a task is created
    handle = sqs.start_message_move_task(
        SourceArn=dlq_arn, MaxNumberOfMessagesPerSecond=10
    )["TaskHandle"]

    def _cancel():
        try:
            sqs.cancel_message_move_task(TaskHandle=handle)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cancel)
    tasks_after_control = sqs.list_message_move_tasks(SourceArn=dlq_arn).get("Results", [])
    # dlq_arn is a freshly created queue, so the control task is the only move task that
    # can ever be associated with it.
    assert len(tasks_after_control) == 1, (
        f"expected exactly 1 move task on a freshly created DLQ after the positive control, "
        f"got {tasks_after_control!r}"
    )


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
