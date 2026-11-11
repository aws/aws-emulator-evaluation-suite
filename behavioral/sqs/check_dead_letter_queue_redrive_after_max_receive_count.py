"""dead-letter-queue-redrive-after-max-receive-count."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "dead-letter-queue-redrive-after-max-receive-count"
GROUP = "state"
SERVICES = ["sqs"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A message received maxReceiveCount times without being deleted is moved to the configured
    dead-letter queue instead of being redelivered from the source queue, whose visible counter
    then polls to 0."""
    sqs = ctx.client("sqs")
    dlq_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-sqs-dlq-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]

    redrive_policy = json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 1})
    src_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-sqs-dlq-src-"),
        Attributes={"VisibilityTimeout": "30", "RedrivePolicy": redrive_policy},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=src_url))

    body = "redrive-me-to-dlq"
    sqs.send_message(QueueUrl=src_url, MessageBody=body)

    # first receive: consumes the message once (ReceiveCount becomes 1, already at
    # maxReceiveCount) but we deliberately do NOT delete it.
    first = _poll_receive_one(sqs, src_url, timeout_s=20.0)
    assert first["Body"] == body, f"expected {body!r} on first receive, got {first['Body']!r}"

    # re-expose it immediately instead of waiting out the visibility timeout: this is the
    # point at which SQS evaluates maxReceiveCount (1), which the first receive already met,
    # so the next active attempt to redeliver from the source must be routed to the DLQ
    # instead of being handed back here.
    sqs.change_message_visibility(
        QueueUrl=src_url, ReceiptHandle=first["ReceiptHandle"], VisibilityTimeout=0
    )

    redelivered_from_src = False
    for _ in range(5):
        resp = sqs.receive_message(QueueUrl=src_url, MaxNumberOfMessages=1, WaitTimeSeconds=2)
        for msg in resp.get("Messages", []):
            redelivered_from_src = True
    assert not redelivered_from_src, (
        f"expected {body!r} to be routed to the DLQ once maxReceiveCount=1 was exceeded, but "
        "it was redelivered from the source queue instead"
    )

    # the message should now show up in the DLQ instead of the source queue. Poll for it,
    # allowing generous time for the asynchronous redrive-move to complete.
    dlq_msg = _poll_receive_one(sqs, dlq_url, timeout_s=90.0)
    assert dlq_msg["Body"] == body, f"expected {body!r} in the DLQ, got {dlq_msg['Body']!r}"
    sqs.delete_message(QueueUrl=dlq_url, ReceiptHandle=dlq_msg["ReceiptHandle"])

    # the source queue's visible counter polls to 0 once the redrive move settles
    _poll_queue_counters(ctx, sqs, src_url, {"ApproximateNumberOfMessages": "0"})


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_queue_counters(ctx, sqs, queue_url, expected, cap_s=90.0):
    """Poll GetQueueAttributes until every named counter equals its expected string value.

    The ApproximateNumberOf* counters may lag up to a minute after producers stop
    (SQS GetQueueAttributes docs), so a single read is not a verdict."""
    budget_s = _budget_s(ctx, cap_s)
    start = time.monotonic()
    stop = start + min(cap_s, budget_s)
    while True:
        attrs = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=list(expected))["Attributes"]
        observed = {name: attrs.get(name) for name in expected}
        if observed == expected:
            return attrs
        if time.monotonic() >= stop:
            if budget_s < cap_s:
                raise TimeoutError(
                    f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
                    f"{cap_s}s counter wait ended (last observed {observed}); not graded"
                )
            raise AssertionError(f"queue counters never reached {expected}; last observed {observed}")
        time.sleep(3)


def _poll_receive_one(sqs, url, timeout_s=20.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=3)
        messages = resp.get("Messages", [])
        if messages:
            return messages[0]
    raise AssertionError(f"no message received from {url} within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
