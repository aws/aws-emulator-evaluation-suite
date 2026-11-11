"""receive-message-respects-max-number-of-messages-cap."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "receive-message-respects-max-number-of-messages-cap"
GROUP = "lifecycle"
SERVICES = ["sqs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A single ReceiveMessage call never returns more messages than MaxNumberOfMessages, and drains fully."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"),
        tags={"sim2real": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    total = 15
    sent_ids = set()
    for i in range(total):
        resp = sqs.send_message(QueueUrl=url, MessageBody=f"cap-check-{i}")
        sent_ids.add(resp["MessageId"])

    received_ids: set[str] = set()
    deadline = time.monotonic() + 30.0
    empty_polls = 0
    while len(received_ids) < total and time.monotonic() < deadline and empty_polls < 5:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=5, WaitTimeSeconds=3)
        batch = resp.get("Messages", [])
        assert len(batch) <= 5, f"ReceiveMessage returned {len(batch)} messages, exceeding MaxNumberOfMessages=5"
        if not batch:
            empty_polls += 1
            continue
        empty_polls = 0
        for m in batch:
            received_ids.add(m["MessageId"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])

    assert received_ids == sent_ids, (
        f"expected to drain all {len(sent_ids)} sent message ids, "
        f"missing={sent_ids - received_ids}, unexpected={received_ids - sent_ids}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
