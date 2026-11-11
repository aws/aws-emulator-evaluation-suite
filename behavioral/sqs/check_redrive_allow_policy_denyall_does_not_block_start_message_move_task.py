"""redrive-allow-policy-denyall-does-not-block-start-message-move-task."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "redrive-allow-policy-denyall-does-not-block-start-message-move-task"
GROUP = "dlq"
SERVICES = ["sqs"]

_TAGS = {"sim2real:managed": "true", "sim2real": "rap-denyall-vs-move-task"}
_TERMINAL = {"COMPLETED", "FAILED", "CANCELLED"}


def _queue_arn(sqs, url: str) -> str:
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]


def _poll(fn, pred, *, timeout_s, interval_s=2.0, budget_s=None):
    start = time.monotonic()
    stop = start + (timeout_s if budget_s is None else min(timeout_s, budget_s))
    val = fn()
    while not pred(val):
        if time.monotonic() >= stop:
            if budget_s is not None and budget_s < timeout_s:
                raise TimeoutError(
                    f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
                    f"{timeout_s}s wait ended (last={val!r}); not graded"
                )
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Once a DLQ's RedriveAllowPolicy reads back denyAll after its source is wired,
    StartMessageMoveTask still completes and returns the DLQ's message to that source, because
    RedriveAllowPolicy gates new RedrivePolicy associations, not the move API."""
    sqs = ctx.client("sqs")
    token = uuid.uuid4().hex[:8]

    dlq_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-dlq-"), tags=_TAGS)[
        "QueueUrl"
    ]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = _queue_arn(sqs, dlq_url)

    src_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-src-"), tags=_TAGS)[
        "QueueUrl"
    ]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=src_url))
    src_arn = _queue_arn(sqs, src_url)

    sqs.set_queue_attributes(
        QueueUrl=dlq_url,
        Attributes={
            "RedriveAllowPolicy": json.dumps(
                {"redrivePermission": "byQueue", "sourceQueueArns": [src_arn]}
            )
        },
    )
    sqs.set_queue_attributes(
        QueueUrl=src_url,
        Attributes={
            "RedrivePolicy": json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 1})
        },
    )

    body = f"{token}-retro"
    sqs.send_message(QueueUrl=src_url, MessageBody=body)

    def _landed_in_dlq():
        for _ in range(8):
            r = sqs.receive_message(
                QueueUrl=src_url, MaxNumberOfMessages=1, WaitTimeSeconds=1, VisibilityTimeout=1
            )
            if not r.get("Messages"):
                break
            time.sleep(2)
        return sqs.get_queue_attributes(
            QueueUrl=dlq_url, AttributeNames=["ApproximateNumberOfMessages"]
        )["Attributes"]["ApproximateNumberOfMessages"]

    landed = _poll(
        _landed_in_dlq, lambda v: v == "1", timeout_s=90.0, budget_s=_budget_s(ctx, 90.0), interval_s=3
    )
    assert landed == "1", (
        f"precondition: {body!r} must have redriven into the DLQ before the move task is "
        f"started; the DLQ's ApproximateNumberOfMessages read {landed!r}"
    )

    # Revoke the allow policy AFTER the association was already used.
    sqs.set_queue_attributes(
        QueueUrl=dlq_url, Attributes={"RedriveAllowPolicy": json.dumps({"redrivePermission": "denyAll"})}
    )
    # SetQueueAttributes changes can take up to 60 s to propagate (SetQueueAttributes docs), so
    # the move starts only once the DLQ reads back denyAll; otherwise it would test nothing.
    def _redrive_permission():
        raw = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["RedriveAllowPolicy"])[
            "Attributes"
        ].get("RedriveAllowPolicy", "{}")
        return json.loads(raw).get("redrivePermission")

    permission = _poll(
        _redrive_permission,
        lambda v: v == "denyAll",
        timeout_s=60.0,
        budget_s=_budget_s(ctx, 60.0),
        interval_s=2,
    )
    assert permission == "denyAll", (
        f"the DLQ's RedriveAllowPolicy never read back denyAll; redrivePermission={permission!r}"
    )

    handle = sqs.start_message_move_task(SourceArn=dlq_arn, DestinationArn=src_arn)["TaskHandle"]
    assert handle, "StartMessageMoveTask returned no TaskHandle despite denyAll"

    def _task():
        results = sqs.list_message_move_tasks(SourceArn=dlq_arn, MaxResults=1).get("Results", [])
        return results[0] if results else {}

    task = _poll(_task, lambda t: t.get("Status") in _TERMINAL, timeout_s=60, interval_s=2)
    assert task.get("Status") == "COMPLETED", (
        f"move task must complete despite RedriveAllowPolicy=denyAll, got {task!r}"
    )

    dlq_count = _poll(
        lambda: sqs.get_queue_attributes(
            QueueUrl=dlq_url, AttributeNames=["ApproximateNumberOfMessages"]
        )["Attributes"]["ApproximateNumberOfMessages"],
        lambda v: v == "0",
        timeout_s=90.0, budget_s=_budget_s(ctx, 90.0),
        interval_s=2,
    )
    assert dlq_count == "0", f"DLQ must be drained by the move despite denyAll, got {dlq_count!r}"

    back = sqs.receive_message(QueueUrl=src_url, MaxNumberOfMessages=1, WaitTimeSeconds=5).get(
        "Messages", []
    )
    assert len(back) == 1 and back[0]["Body"] == body, (
        f"expected the message {body!r} moved back to the source despite denyAll, got {back!r}"
    )
    sqs.delete_message(QueueUrl=src_url, ReceiptHandle=back[0]["ReceiptHandle"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
