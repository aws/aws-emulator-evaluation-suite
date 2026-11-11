"""message-retention-period-expires-undeleted-message."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "message-retention-period-expires-undeleted-message"
GROUP = 'invariants'
SERVICES = ['sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": "message-retention-period-expiry"}

# On real SQS ApproximateNumberOfMessages can read 0 while ReceiveMessage still returns the expired
# message, so receivability is polled first and the counter asserted afterwards.
# 240s bounds the poll; the assertion is on the eventual state, not on a deadline.
_EXPIRY_CEILING_S = 240
_EMPTY_POLLS = 3


def _poll(fn, pred, *, timeout_s, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _depth(sqs, url):
    return sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"],
    )["Attributes"].get("ApproximateNumberOfMessages", "?")


# timing:real-time — retention: 60 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SetQueueAttributes.html
@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A message on a MessageRetentionPeriod=60 queue becomes unreceivable once retention elapses,
    with no delete, while the same message on a default four-day retention queue is still there.
    """
    sqs = ctx.client("sqs")
    marker = f"retention-marker-{uuid.uuid4().hex[:8]}"

    # 60 is the API MINIMUM for MessageRetentionPeriod; the window cannot be made shorter.
    url_short = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"),
        Attributes={"MessageRetentionPeriod": "60"},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url_short))

    url_long = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"), tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url_long))

    short_attrs = sqs.get_queue_attributes(
        QueueUrl=url_short, AttributeNames=["All"])["Attributes"]
    assert short_attrs.get("MessageRetentionPeriod") == "60", (
        f"the short queue did not take the 60s retention, so nothing below is an expiry test: "
        f"MessageRetentionPeriod={short_attrs.get('MessageRetentionPeriod')!r}"
    )
    long_attrs = sqs.get_queue_attributes(
        QueueUrl=url_long, AttributeNames=["All"])["Attributes"]
    assert long_attrs.get("MessageRetentionPeriod") == "345600", (
        f"the control queue must carry the DEFAULT four-day retention or it is not a control: "
        f"MessageRetentionPeriod={long_attrs.get('MessageRetentionPeriod')!r}"
    )

    sqs.send_message(QueueUrl=url_short, MessageBody=marker)
    sqs.send_message(QueueUrl=url_long, MessageBody=marker)

    # Prove the message landed and was receivable first. Retention runs off SentTimestamp, so
    # receives at VisibilityTimeout=0 neither hold the message nor change the expiry.
    pre_depth = _poll(lambda: _depth(sqs, url_short), lambda v: v == "1",
                      timeout_s=60)
    assert pre_depth == "1", (
        f"the message never landed on the short-retention queue, so nothing below proves "
        f"retention: ApproximateNumberOfMessages={pre_depth!r}"
    )
    pre_msgs = []
    pre_deadline = time.monotonic() + 30
    while not pre_msgs and time.monotonic() < pre_deadline:
        pre_msgs = sqs.receive_message(
            QueueUrl=url_short, MaxNumberOfMessages=1, WaitTimeSeconds=2, VisibilityTimeout=0,
        ).get("Messages", [])
    assert [m["Body"] for m in pre_msgs] == [marker], (
        f"the message was counted but never receivable, so the disappearance below is not an "
        f"expiry: got {[m['Body'] for m in pre_msgs]!r}, expected {[marker]!r}"
    )

    # Poll receivability, not the counter (see _EXPIRY_CEILING_S). MaxNumberOfMessages=1: with
    # VisibilityTimeout=0 and a batch of 10, real SQS can return the same message ten times.
    last_bodies = [marker]
    empties = 0
    expiry_deadline = time.monotonic() + _EXPIRY_CEILING_S
    while empties < _EMPTY_POLLS and time.monotonic() < expiry_deadline:
        last_bodies = [m["Body"] for m in sqs.receive_message(
            QueueUrl=url_short, MaxNumberOfMessages=1, WaitTimeSeconds=2, VisibilityTimeout=0,
        ).get("Messages", [])]
        empties = empties + 1 if not last_bodies else 0
    assert empties >= _EMPTY_POLLS, (
        f"a message past its 60s MessageRetentionPeriod was still being delivered after "
        f"{_EXPIRY_CEILING_S}s: the last poll returned {last_bodies!r}. Retention expiry did "
        f"not run"
    )

    short_depth_after = _poll(lambda: _depth(sqs, url_short), lambda v: v == "0",
                              timeout_s=60)
    assert short_depth_after == "0", (
        f"the message stopped being receivable but ApproximateNumberOfMessages did not return to "
        f"0: {short_depth_after!r} -- the queue still counts a message it will never deliver"
    )

    # The control, read last, attributes the disappearance to retention.
    long_msgs = []
    for _ in range(3):
        long_msgs += sqs.receive_message(
            QueueUrl=url_long, MaxNumberOfMessages=10, WaitTimeSeconds=5,
        ).get("Messages", [])
        if long_msgs:
            break
    assert [m["Body"] for m in long_msgs] == [marker], (
        f"the control queue with the default four-day retention lost its message too, so the "
        f"disappearance above was not retention: {[m['Body'] for m in long_msgs]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
