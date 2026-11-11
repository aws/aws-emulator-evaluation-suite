"""op-message-move-task-on-non-dlq-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-message-move-task-on-non-dlq-rejected"
GROUP = 'errors'
SERVICES = ['sqs']

# Exact messages real SQS returns for these refusals.
MSG_NOT_DLQ = 'Source queue must be configured as a Dead Letter Queue.'


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected rejection but call succeeded and returned {result!r}")


def _redrive_policy(dlq_arn, max_receive_count=2):
    return json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": max_receive_count})


def _start_move_task_eventually(sqs, arn, *, timeout_s=20.0, interval_s=2.0):
    """RedrivePolicy wiring propagates asynchronously, so a freshly-configured DLQ can
    still answer InvalidParameterValue for a few seconds. Retry only on that code with the
    not-a-DLQ message; any other rejection is a real failure and raises immediately."""
    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            return sqs.start_message_move_task(SourceArn=arn)
        except ClientError as exc:
            last_error = exc.response.get("Error", {})
            if (
                last_error.get("Code") != "InvalidParameterValue"
                or last_error.get("Message") != MSG_NOT_DLQ
            ):
                raise AssertionError(f"rejected unexpectedly: {last_error!r}") from exc
            time.sleep(interval_s)
    raise AssertionError(f"still rejected after {timeout_s}s: {last_error!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartMessageMoveTask rejects a source queue that is no queue's dead-letter queue, and accepts
    the same call once that queue is wired as a DLQ, so the refusal tracks DLQ status."""
    sqs = ctx.client("sqs")

    candidate_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=candidate_url))
    candidate_arn = sqs.get_queue_attributes(
        QueueUrl=candidate_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    # Positive control: an independently-wired, already-valid DLQ accepts the call, so a
    # target that blanket-denies StartMessageMoveTask cannot pass this check.
    control_dlq_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=control_dlq_url))
    control_dlq_arn = sqs.get_queue_attributes(
        QueueUrl=control_dlq_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]
    control_src_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"),
        Attributes={"RedrivePolicy": _redrive_policy(control_dlq_arn)},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=control_src_url))
    sqs.send_message(QueueUrl=control_dlq_url, MessageBody="positive-control")

    resp = _start_move_task_eventually(sqs, control_dlq_arn)
    assert resp.get("TaskHandle"), f"positive control returned no TaskHandle: {resp!r}"

    # Break: candidate_arn is not referenced by any queue's RedrivePolicy, so it is not
    # a dead-letter queue.
    error = _client_error(lambda: sqs.start_message_move_task(SourceArn=candidate_arn))
    assert error.get("Code") == "InvalidParameterValue", f"got {error!r}"
    assert error.get("Message") == MSG_NOT_DLQ, f"got {error!r}"

    # Effect absent: no task was started for the rejected candidate.
    tasks = sqs.list_message_move_tasks(SourceArn=candidate_arn).get("Results", [])
    assert tasks == [], f"expected no move tasks for non-DLQ candidate, got {tasks}"

    # Restore: wire another queue's RedrivePolicy at the same candidate ARN, making it a
    # real DLQ, then re-issue the identical call and demand success.
    restoring_src_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"),
        Attributes={"RedrivePolicy": _redrive_policy(candidate_arn)},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=restoring_src_url))
    sqs.send_message(QueueUrl=candidate_url, MessageBody="restored")

    resp = _start_move_task_eventually(sqs, candidate_arn, timeout_s=90.0, interval_s=3.0)
    assert resp.get("TaskHandle"), f"restored DLQ returned no TaskHandle: {resp!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
