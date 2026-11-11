"""dlq-move-withheld-until-the-maxreceivecount-th-delivery."""

from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "dlq-move-withheld-until-the-maxreceivecount-th-delivery"
GROUP = "visibility_dlq"
SERVICES = ["sqs"]

# 3 so that moving on an early receive is distinguishable from moving on time.
_MAX_RECEIVE_COUNT = 3
_MOVE_S = 90.0  # bounded wait for the asynchronous source -> DLQ move
_COUNTER_S = 120.0  # bounded wait for the documented >=1min counter consistency window

_TAGS = {
    "sim2real:managed": "true",
    "sim2real": "dlq-move-withheld",
}


def _queue_arn(sqs, url: str) -> str:
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]


def _receive(sqs, url, *, wait_s=2):
    """One ReceiveMessage with the system attributes this check reads. Never swallows errors."""
    return sqs.receive_message(
        QueueUrl=url,
        MaxNumberOfMessages=10,
        WaitTimeSeconds=wait_s,
        MessageSystemAttributeNames=["All"],
    ).get("Messages", [])


def _await_delivery(sqs, url, *, token, timeout_s, what):
    """Bounded poll until the tokened message is delivered from `url`; RAISES on the deadline.

    Non-matching messages are re-exposed with ChangeMessageVisibility(0); nothing is deleted.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for msg in _receive(sqs, url):
            if token in msg["Body"]:
                return msg
            sqs.change_message_visibility(
                QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"], VisibilityTimeout=0
            )
    raise AssertionError(f"{what}: {token!r} was not delivered from {url} within {timeout_s}s")


def _await_dlq_move(sqs, src_url, dlq_url, *, token, timeout_s, what):
    """Drive and observe the source -> DLQ move; RAISES on the deadline.

    SQS evaluates the redrive policy when a ReceiveMessage attempts redelivery, so each round
    receives from the source before reading the DLQ.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for msg in _receive(sqs, src_url, wait_s=1):
            sqs.change_message_visibility(
                QueueUrl=src_url, ReceiptHandle=msg["ReceiptHandle"], VisibilityTimeout=0
            )
        for msg in _receive(sqs, dlq_url, wait_s=1):
            if token in msg["Body"]:
                return msg
            sqs.change_message_visibility(
                QueueUrl=dlq_url, ReceiptHandle=msg["ReceiptHandle"], VisibilityTimeout=0
            )
    raise AssertionError(f"{what}: {token!r} did not reach the DLQ within {timeout_s}s")


def _await_attribute(sqs, url, name, want, *, timeout_s, why):
    """Bounded poll until GetQueueAttributes reports `want` for `name`; RAISES on the deadline."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=[name])["Attributes"].get(
            name
        )
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
    """With maxReceiveCount=3 the source delivers ApproximateReceiveCount 1, 2, 3 while the DLQ
    stays empty; only then the byte-identical body is in the DLQ and the source drains to 0.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html
    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_GetQueueAttributes.html
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
            # 30s is only a ceiling: every redelivery below is forced with
            # ChangeMessageVisibility(0), so the check never waits out a visibility timeout.
            "VisibilityTimeout": "30",
            "RedrivePolicy": json.dumps(
                {"deadLetterTargetArn": dlq_arn, "maxReceiveCount": _MAX_RECEIVE_COUNT}
            ),
        },
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=src_url))

    # The policy must actually be on the queue, or every verdict below is about a queue with no
    # redrive policy at all.
    policy = json.loads(
        sqs.get_queue_attributes(QueueUrl=src_url, AttributeNames=["RedrivePolicy"])["Attributes"][
            "RedrivePolicy"
        ]
    )
    assert int(policy["maxReceiveCount"]) == _MAX_RECEIVE_COUNT, (
        f"the source queue's maxReceiveCount is {policy.get('maxReceiveCount')!r}, not "
        f"{_MAX_RECEIVE_COUNT}; the delivery-count assertions below would be measuring the wrong "
        f"policy"
    )
    assert policy["deadLetterTargetArn"] == dlq_arn, (
        f"the source queue's deadLetterTargetArn is {policy.get('deadLetterTargetArn')!r}, not "
        f"the DLQ this check created ({dlq_arn})"
    )

    token = uuid.uuid4().hex[:8]
    body = f"poison-{token}"
    sqs.send_message(QueueUrl=src_url, MessageBody=body)

    # --- deliveries 1..N must all come from the SOURCE, correctly counted ---------------
    for expected_count in range(1, _MAX_RECEIVE_COUNT + 1):
        msg = _await_delivery(
            sqs,
            src_url,
            token=token,
            timeout_s=30.0,
            what=f"delivery {expected_count} of {_MAX_RECEIVE_COUNT}",
        )
        assert msg["Body"] == body, (
            f"delivery {expected_count} from the source carried body {msg['Body']!r}, expected "
            f"{body!r}"
        )
        got_count = msg["Attributes"]["ApproximateReceiveCount"]
        assert got_count == str(expected_count), (
            f"delivery {expected_count} of {_MAX_RECEIVE_COUNT} reported "
            f"ApproximateReceiveCount={got_count!r}; the counter must advance 1,2,...,"
            f"{_MAX_RECEIVE_COUNT} across redeliveries from the source"
        )
        # Corroborating second observable: with ReceiveCount == expected_count <=
        # maxReceiveCount, the move is not yet due, so the DLQ must hold nothing of ours.
        early = [m for m in _receive(sqs, dlq_url, wait_s=1) if token in m["Body"]]
        assert not early, (
            f"the message reached the DLQ after only {expected_count} source "
            f"deliver{'y' if expected_count == 1 else 'ies'} (maxReceiveCount="
            f"{_MAX_RECEIVE_COUNT}): the redrive policy was evaluated too early"
        )
        # Force the next redelivery instead of waiting out the visibility timeout.
        sqs.change_message_visibility(
            QueueUrl=src_url, ReceiptHandle=msg["ReceiptHandle"], VisibilityTimeout=0
        )

    # --- the move: an independent read at the DESTINATION ------------------------------
    moved = _await_dlq_move(
        sqs,
        src_url,
        dlq_url,
        token=token,
        timeout_s=_MOVE_S,
        what=(
            f"after {_MAX_RECEIVE_COUNT} source deliveries the message must move to the DLQ, "
            f"but nothing arrived there"
        ),
    )
    assert moved["Body"] == body, (
        f"the DLQ copy is not byte-identical to what was sent: got {moved['Body']!r}, expected "
        f"{body!r}"
    )
    # Deliberately not asserted: whether the DLQ copy's ApproximateReceiveCount restarts at 1 or
    # continues from the source's count; the docs do not say.
    sqs.delete_message(QueueUrl=dlq_url, ReceiptHandle=moved["ReceiptHandle"])

    # --- and it is GONE from the source, not copied ------------------------------------
    _await_attribute(
        sqs,
        src_url,
        "ApproximateNumberOfMessages",
        "0",
        timeout_s=_COUNTER_S,
        why=(
            "a redrive MOVES the message; a source that still counts it was implemented as a copy"
        ),
    )
    left = [m["Body"] for m in _receive(sqs, src_url, wait_s=2) if token in m["Body"]]
    assert left == [], (
        f"the source still delivers the redriven message {left!r}; the move must remove it from "
        f"the source, not duplicate it into the DLQ"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
