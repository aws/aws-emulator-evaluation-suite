"""fifo-dedup-scope-message-group-allows-same-dedup-id-in-different-groups."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "fifo-dedup-scope-message-group-allows-same-dedup-id-in-different-groups"
GROUP = 'fifo'
SERVICES = ['sqs']

# `sim2real:managed=true` lets account cleanup find the queues via the Resource Groups Tagging API.
_TAGS = {"sim2real:managed": "true", "sim2real": "fifo-dedup-scope-message-group"}

def _drain(sqs, url, *, timeout_s, wait_s=5, empty_polls=2):
    """Receive-and-delete until `empty_polls` consecutive empty polls or the deadline; -> [msg].

    Deleting matters: a FIFO message group is blocked while any of its messages is in flight.
    """
    got, empties = [], 0
    deadline = time.monotonic() + timeout_s
    while empties < empty_polls and time.monotonic() < deadline:
        batch = sqs.receive_message(
            # Both forms: AttributeNames is deprecated but honoured, and SQS accepts both together.
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s,
            AttributeNames=["All"], MessageSystemAttributeNames=["All"],
        ).get("Messages", [])
        if not batch:
            empties += 1
            continue
        empties = 0
        for m in batch:
            got.append(m)
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    return got


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """DeduplicationScope=messageGroup confines FIFO dedup to one group: the same dedup id in two
    groups yields two deliveries, the default queue scope yields one, and one group still dedups.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/high-throughput-fifo.html
    """
    sqs = ctx.client("sqs")
    token = uuid.uuid4().hex[:8]

    # Queue A: high-throughput FIFO. Both attributes must be set AT CREATE -- setting
    # DeduplicationScope on an existing queue is legal but takes up to 60s to take effect, which
    # would make the first send race the configuration.
    url_a = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + ".fifo",
        Attributes={"FifoQueue": "true", "DeduplicationScope": "messageGroup",
                    "FifoThroughputLimit": "perMessageGroupId", "VisibilityTimeout": "30"},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url_a))

    # Queue B: plain FIFO, so DeduplicationScope defaults to `queue`.
    url_b = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + ".fifo",
        Attributes={"FifoQueue": "true", "VisibilityTimeout": "30"},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url_b))

    attrs_a = sqs.get_queue_attributes(
        QueueUrl=url_a, AttributeNames=["All"])["Attributes"]
    assert attrs_a.get("DeduplicationScope") == "messageGroup", (
        f"queue A is not message-group-scoped, so nothing below distinguishes the two scopes: "
        f"DeduplicationScope={attrs_a.get('DeduplicationScope')!r}"
    )
    assert attrs_a.get("FifoThroughputLimit") == "perMessageGroupId", (
        f"queue A is not high-throughput FIFO: "
        f"FifoThroughputLimit={attrs_a.get('FifoThroughputLimit')!r}"
    )
    attrs_b = sqs.get_queue_attributes(
        QueueUrl=url_b, AttributeNames=["All"])["Attributes"]
    assert attrs_b.get("DeduplicationScope", "queue") == "queue", (
        f"the contrast queue B must carry the DEFAULT queue-wide scope, got "
        f"{attrs_b.get('DeduplicationScope')!r}"
    )

    g1, g2 = f"g1-{token}", f"g2-{token}"
    dedup_d = f"dedup-D-{token}"
    body_g1, body_g2 = f"body-in-{g1}", f"body-in-{g2}"

    for url in (url_a, url_b):
        sqs.send_message(QueueUrl=url, MessageBody=body_g1,
                         MessageGroupId=g1, MessageDeduplicationId=dedup_d)
        sqs.send_message(QueueUrl=url, MessageBody=body_g2,
                         MessageGroupId=g2, MessageDeduplicationId=dedup_d)

    a_msgs = _drain(sqs, url_a, timeout_s=90)
    a_bodies = sorted(m["Body"] for m in a_msgs)
    assert a_bodies == sorted([body_g1, body_g2]), (
        f"DeduplicationScope=messageGroup must NOT deduplicate across groups: expected both "
        f"bodies {sorted([body_g1, body_g2])!r}, got {a_bodies!r}"
    )
    a_groups = {m["Attributes"]["MessageGroupId"] for m in a_msgs}
    assert a_groups == {g1, g2}, (
        f"the two deliveries did not come from the two distinct groups: got groups {a_groups!r}, "
        f"expected {{{g1!r}, {g2!r}}}"
    )

    b_msgs = _drain(sqs, url_b, timeout_s=90)
    b_bodies = [m["Body"] for m in b_msgs]
    assert len(b_bodies) == 1, (
        f"the default DeduplicationScope=queue must deduplicate ACROSS groups: expected exactly "
        f"1 delivery, got {len(b_bodies)} ({b_bodies!r})"
    )
    assert b_bodies == [body_g1], (
        f"queue-scoped deduplication must keep the FIRST send and discard the second, got "
        f"{b_bodies!r} (expected {[body_g1]!r})"
    )

    # Control: narrowing the scope must not switch deduplication off.
    dedup_e = f"dedup-E-{token}"
    sqs.send_message(QueueUrl=url_a, MessageBody=f"E-first-{token}",
                     MessageGroupId=g1, MessageDeduplicationId=dedup_e)
    sqs.send_message(QueueUrl=url_a, MessageBody=f"E-second-{token}",
                     MessageGroupId=g1, MessageDeduplicationId=dedup_e)
    e_bodies = [m["Body"] for m in _drain(sqs, url_a, timeout_s=90)]
    assert e_bodies == [f"E-first-{token}"], (
        f"the same dedup id in the SAME group must still deduplicate under messageGroup scope, "
        f"keeping the first send: got {e_bodies!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
