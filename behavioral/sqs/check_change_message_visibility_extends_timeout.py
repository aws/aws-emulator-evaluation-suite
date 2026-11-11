"""change-message-visibility-extends-timeout."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "change-message-visibility-extends-timeout"
GROUP = "state"
SERVICES = ["sqs"]


# timing:real-time — visibility: 12 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """ChangeMessageVisibility extends the hidden window past the queue's original
    VisibilityTimeout; the message stays hidden through the original deadline and only
    reappears once the *extended* deadline elapses."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-sqs-cvt-"),
        Attributes={"VisibilityTimeout": "3"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    body = "cvt-extend-message"
    sqs.send_message(QueueUrl=url, MessageBody=body)
    msg = _poll_receive_one(sqs, url, timeout_s=15.0)
    assert msg["Body"] == body

    t_change = time.monotonic()
    sqs.change_message_visibility(
        QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"], VisibilityTimeout=12
    )

    # Hold well past the queue's *original* 3s timeout, polling receive throughout
    # (bounded retry, not a single sample after a blind sleep): every sample in the
    # hold window must find the message still hidden, which is what proves the
    # extension actually moved the deadline rather than merely delaying one check.
    hold_deadline = t_change + 9.0
    while time.monotonic() < hold_deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
        assert not resp.get("Messages"), (
            f"message reappeared {time.monotonic() - t_change:.1f}s after "
            "ChangeMessageVisibility, before the extended 12s window elapsed"
        )

    # Poll (bounded) for it to reappear once the extended window elapses, and assert
    # the reappearance tracks the *extended* deadline, not the original 3s one.
    second = _poll_receive_one(sqs, url, timeout_s=20.0)
    reappeared_at = time.monotonic() - t_change
    assert second["Body"] == body
    assert reappeared_at >= 9.0, (
        f"message reappeared only {reappeared_at:.1f}s after ChangeMessageVisibility, "
        "inside the window we already held open above -- the extended visibility "
        "did not hold"
    )
    sqs.delete_message(QueueUrl=url, ReceiptHandle=second["ReceiptHandle"])


def _poll_receive_one(sqs, url, timeout_s=15.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2)
        messages = resp.get("Messages", [])
        if messages:
            return messages[0]
    raise AssertionError(f"no message received within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
