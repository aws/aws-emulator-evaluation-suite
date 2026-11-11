"""dlq-moves-only-the-undeleted-message-after-four-deliveries."""

from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "dlq-moves-only-the-undeleted-message-after-four-deliveries"
GROUP = "visibility_dlq"
SERVICES = ["sqs"]

_MAX_RECEIVE_COUNT = 4
_HEALTHY_DELETED_AT = 2  # the healthy message is deleted on this delivery, below the count
_MOVE_S = 40.0  # bounded wait for the asynchronous source -> DLQ move
_COUNTER_S = 40.0  # bounded wait for the approximate counters to converge

_TAGS = {
    "sim2real:managed": "true",
    "sim2real": "dlq-moves-only-undeleted",
}


def _queue_arn(sqs, url: str) -> str:
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]


def _receive(sqs, url, *, wait_s=2):
    """One ReceiveMessage with the attributes this check reads. Never swallows errors."""
    return sqs.receive_message(
        QueueUrl=url,
        MaxNumberOfMessages=10,
        WaitTimeSeconds=wait_s,
        MessageSystemAttributeNames=["All"],
        MessageAttributeNames=["All"],
    ).get("Messages", [])


def _await_dlq_move(sqs, src_url, dlq_url, *, token, timeout_s, what):
    """Drive and observe the source -> DLQ move; RAISES on the deadline.

    SQS evaluates the redrive policy when a ReceiveMessage attempts redelivery, so each round
    receives from the source before reading the DLQ.
    """
    deadline = time.monotonic() + timeout_s
    last: list = []
    while time.monotonic() < deadline:
        for msg in _receive(sqs, src_url, wait_s=1):
            sqs.change_message_visibility(
                QueueUrl=src_url, ReceiptHandle=msg["ReceiptHandle"], VisibilityTimeout=0
            )
        dlq_msgs = _receive(sqs, dlq_url, wait_s=1)
        last = [m["Body"] for m in dlq_msgs]
        for msg in dlq_msgs:
            if token in msg["Body"]:
                return msg
            sqs.change_message_visibility(
                QueueUrl=dlq_url, ReceiptHandle=msg["ReceiptHandle"], VisibilityTimeout=0
            )
    raise AssertionError(
        f"{what}: {token!r} did not reach the DLQ within {timeout_s}s; last DLQ read {last!r}"
    )


def _await_attribute(sqs, url, name, want, *, timeout_s, why):
    """Bounded poll until GetQueueAttributes reports `want` for `name`; RAISES on the deadline."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=[name])["Attributes"].get(name)
        if last == want:
            return last
        time.sleep(2)
    raise AssertionError(
        f"{name} on {url} never reached {want!r} within {timeout_s}s (last={last!r}); {why}"
    )


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """With maxReceiveCount=4, a healthy message deleted on its 2nd delivery never moves, while an
    undeleted one is delivered with ApproximateReceiveCount 1..4 and only then reaches the DLQ with
    its MessageId, body and attribute intact; the DLQ holds nothing but that message.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html
    """
    sqs = ctx.client("sqs")

    dlq_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-dlq-"), tags=_TAGS)[
        "QueueUrl"
    ]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = _queue_arn(sqs, dlq_url)

    src_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-src-"),
        Attributes={
            # Only a ceiling: every redelivery is forced with ChangeMessageVisibility(0).
            "VisibilityTimeout": "30",
            "RedrivePolicy": json.dumps(
                {"deadLetterTargetArn": dlq_arn, "maxReceiveCount": str(_MAX_RECEIVE_COUNT)}
            ),
        },
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=src_url))

    policy = json.loads(
        sqs.get_queue_attributes(QueueUrl=src_url, AttributeNames=["RedrivePolicy"])["Attributes"][
            "RedrivePolicy"
        ]
    )
    assert (policy["deadLetterTargetArn"], int(policy["maxReceiveCount"])) == (
        dlq_arn,
        _MAX_RECEIVE_COUNT,
    ), f"the source queue's RedrivePolicy reads back {policy!r}, not this check's DLQ and count"

    token = uuid.uuid4().hex[:8]
    poison = f"poison-{token}-ünïcode"
    healthy = f"healthy-{token}"
    attr = {"kind": {"DataType": "String", "StringValue": f"order-{token}"}}
    poison_id = sqs.send_message(QueueUrl=src_url, MessageBody=poison, MessageAttributes=attr)[
        "MessageId"
    ]
    sqs.send_message(QueueUrl=src_url, MessageBody=healthy)

    # Distinct ApproximateReceiveCount values in order of first sight; a duplicate copy that
    # repeats a count does not add one.
    counts: dict[str, list[int]] = {poison: [], healthy: []}
    healthy_deleted = False
    deadline = time.monotonic() + 40.0
    while time.monotonic() < deadline and not (
        _MAX_RECEIVE_COUNT in counts[poison] and healthy_deleted
    ):
        for msg in _receive(sqs, src_url, wait_s=1):
            body = msg["Body"]
            assert body in counts, f"the source delivered a body this check never sent: {body!r}"
            n = int(msg["Attributes"]["ApproximateReceiveCount"])
            if n not in counts[body]:
                counts[body].append(n)
            if body == healthy and n >= _HEALTHY_DELETED_AT:
                sqs.delete_message(QueueUrl=src_url, ReceiptHandle=msg["ReceiptHandle"])
                healthy_deleted = True
                continue
            if body == poison and n < _MAX_RECEIVE_COUNT:
                early = [m for m in _receive(sqs, dlq_url, wait_s=1) if token in m["Body"]]
                assert not early, (
                    f"a message reached the DLQ after a delivery with ApproximateReceiveCount {n} "
                    f"(maxReceiveCount={_MAX_RECEIVE_COUNT})"
                )
            # Re-expose; after the last allowed delivery the next attempt must redrive it.
            sqs.change_message_visibility(
                QueueUrl=src_url, ReceiptHandle=msg["ReceiptHandle"], VisibilityTimeout=0
            )
    want_poison = list(range(1, _MAX_RECEIVE_COUNT + 1))
    assert counts[poison] == want_poison, (
        f"the undeleted message's distinct ApproximateReceiveCount values ran {counts[poison]!r}, "
        f"expected {want_poison!r}"
    )
    want_healthy = list(range(1, _HEALTHY_DELETED_AT + 1))
    assert healthy_deleted and counts[healthy][: len(want_healthy)] == want_healthy, (
        f"the healthy message's distinct ApproximateReceiveCount values ran {counts[healthy]!r}, "
        f"expected to start {want_healthy!r} before its delete"
    )

    moved = _await_dlq_move(
        sqs,
        src_url,
        dlq_url,
        token=token,
        timeout_s=_MOVE_S,
        what=f"after {_MAX_RECEIVE_COUNT} deliveries the undeleted message must move to the DLQ",
    )
    assert moved["Body"] == poison, (
        f"the DLQ copy carries body {moved['Body']!r}, expected {poison!r}"
    )
    got_attr = moved.get("MessageAttributes", {}).get("kind", {})
    assert (got_attr.get("DataType"), got_attr.get("StringValue")) == (
        "String",
        f"order-{token}",
    ), f"the DLQ copy carries message attribute {got_attr!r}, expected the one sent"
    sqs.delete_message(QueueUrl=dlq_url, ReceiptHandle=moved["ReceiptHandle"])

    # The healthy message was deleted below the count: it must never surface in the DLQ. Any
    # further DLQ copy can only be a duplicate of the redriven message, with its MessageId.
    dlq_ids = {moved["MessageId"]}
    while msgs := _receive(sqs, dlq_url, wait_s=2):
        for m in msgs:
            assert m["Body"] == poison, (
                f"the DLQ holds a message besides the redriven one: {m['Body']!r}"
            )
            dlq_ids.add(m["MessageId"])
            sqs.delete_message(QueueUrl=dlq_url, ReceiptHandle=m["ReceiptHandle"])
    assert dlq_ids == {poison_id}, (
        f"the DLQ copies carry {len(dlq_ids)} MessageId(s), expected only the redriven message's"
    )
    _await_attribute(
        sqs,
        src_url,
        "ApproximateNumberOfMessages",
        "0",
        timeout_s=_COUNTER_S,
        why="a redrive MOVES the message; a source that still counts it was implemented as a copy",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
