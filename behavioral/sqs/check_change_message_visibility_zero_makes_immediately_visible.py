"""change-message-visibility-zero-makes-immediately-visible."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "change-message-visibility-zero-makes-immediately-visible"
GROUP = "state"
SERVICES = ["sqs"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ChangeMessageVisibility with VisibilityTimeout=0 makes the message receivable again well before
    its long original timeout; a control leg first proves that long timeout is in effect.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-sqs-cvz-"),
        Attributes={"VisibilityTimeout": "120"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    body = "cvz-immediate-message"
    t0 = time.monotonic()
    sqs.send_message(QueueUrl=url, MessageBody=body)
    msg = _poll_receive_one(sqs, url, timeout_s=15.0)
    first_receive_latency_s = time.monotonic() - t0
    assert msg["Body"] == body, f"expected body {body!r}, got {msg['Body']!r}"

    # Control: the 120s queue timeout must still hide the message after >=3x its first delivery
    # latency, or the VT=0 leg cannot tell a real override from no enforcement at all.
    hold_window_s = max(3.0 * first_receive_latency_s, 5.0)
    still_hidden = _poll_receive_one(sqs, url, timeout_s=hold_window_s, expect_none=True)
    assert still_hidden is None, (
        f"expected message to remain hidden under the 120s VisibilityTimeout for "
        f"{hold_window_s:.1f}s, but it reappeared: {still_hidden!r}"
    )

    sqs.change_message_visibility(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"], VisibilityTimeout=0)

    # Well under the 120s original timeout, the message must already be receivable again.
    second = _poll_receive_one(sqs, url, timeout_s=10.0)
    assert second["Body"] == body, f"expected body {body!r} after VT=0, got {second['Body']!r}"
    sqs.delete_message(QueueUrl=url, ReceiptHandle=second["ReceiptHandle"])


def _poll_receive_one(sqs, url, timeout_s=15.0, expect_none=False):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2)
        messages = resp.get("Messages", [])
        if messages:
            return messages[0]
    if expect_none:
        return None
    raise AssertionError(f"no message received within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
