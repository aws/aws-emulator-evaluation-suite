"""e2e-work-queue-pattern."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "e2e-work-queue-pattern"
GROUP = 'e2e_workflows'
SERVICES = ['sqs']
_TAGS = {"sim2real:managed": "true", "sim2real": "e2e-work-queue-pattern"}

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Full worker pattern: send 5 messages, receive-process-delete loop, verify empty."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    token = uuid.uuid4().hex[:8]
    bodies = {f"work-{i}-{token}" for i in range(5)}
    for body in bodies:
        sqs.send_message(QueueUrl=url, MessageBody=body)

    # Worker loop: receive, "process", delete
    processed: set[str] = set()
    for _ in range(20):
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        messages = resp.get("Messages", [])
        if not messages:
            if processed == bodies:
                break
            continue
        for msg in messages:
            processed.add(msg["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
        if processed == bodies:
            break

    if processed != bodies:
        raise AssertionError(
            f"processed {len(processed)} messages, expected {len(bodies)}: "
            f"missing={bodies - processed}"
        )
    # Verify queue is empty via two independent observables: a direct receive and
    # the queue's own reported approximate count.
    _leftover = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1).get("Messages", [])
    assert not _leftover, f"expected no messages, got {len(_leftover)}"
    _approx = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]["ApproximateNumberOfMessages"]
    assert _approx == "0", f"expected ApproximateNumberOfMessages '0', got {_approx!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
