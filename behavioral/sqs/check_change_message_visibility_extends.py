"""change-message-visibility-extends."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "change-message-visibility-extends"
GROUP = 'visibility_dlq'
SERVICES = ['sqs']

# timing:real-time — visibility: 10 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """ChangeMessageVisibility extends invisibility past the original 2s VisibilityTimeout, but
    boundedly: the message stays hidden past 2s and reappears once the extended 10s deadline passes.
    """
    sqs = ctx.client("sqs")
    original_vt = 2
    extended_vt = 10
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"),
        Attributes={"VisibilityTimeout": str(original_vt)},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    sqs.send_message(QueueUrl=url, MessageBody="vis-extend-test")
    msg = _poll_receive_one(sqs, url, timeout_s=15.0)

    t_extend = time.monotonic()
    sqs.change_message_visibility(
        QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"], VisibilityTimeout=extended_vt
    )

    # Past the original VT but well inside the extended VT, the message must stay hidden.
    hold_deadline = t_extend + (extended_vt - 3)
    checked_past_original_vt = False
    while time.monotonic() < hold_deadline:
        elapsed = time.monotonic() - t_extend
        if elapsed >= original_vt + 0.5:
            checked_past_original_vt = True
            resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=0)
            visible = resp.get("Messages", [])
            assert not visible, (
                f"message visible at {elapsed:.1f}s despite ChangeMessageVisibility "
                f"extending to {extended_vt}s (original VT was {original_vt}s): {visible}"
            )
        time.sleep(1)
    assert checked_past_original_vt, (
        "hold window ended before a read landed past the original VT -- widen it"
    )

    # The extension must be bounded: the same message must reappear after the extended deadline,
    # which catches a target that hides it forever.
    reappeared = _poll_receive_one(
        sqs, url, timeout_s=extended_vt + 15.0, expected_message_id=msg["MessageId"]
    )
    reappeared_at = time.monotonic() - t_extend
    assert reappeared_at >= extended_vt - 1, (
        f"message reappeared at {reappeared_at:.1f}s, before the extended VT of "
        f"{extended_vt}s had elapsed -- extension did not hold for its full duration"
    )
    sqs.delete_message(QueueUrl=url, ReceiptHandle=reappeared["ReceiptHandle"])


def _poll_receive_one(sqs, url, timeout_s, expected_message_id=None):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2)
        for m in resp.get("Messages", []):
            if expected_message_id is None or m["MessageId"] == expected_message_id:
                return m
    raise AssertionError(f"no matching message received within {timeout_s:.0f}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
