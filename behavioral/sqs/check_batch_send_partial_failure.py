"""batch-send-partial-failure."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-send-partial-failure"
GROUP = 'errors'
SERVICES = ['sqs']

ERR_INVALID_PARAMETER = "InvalidParameterValue"


def _drain(sqs, url, *, timeout_s):
    """Receive-and-delete every distinct message that shows up inside timeout_s."""
    seen, bodies = set(), []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
        for msg in resp.get("Messages", []):
            if msg["MessageId"] not in seen:
                seen.add(msg["MessageId"])
                bodies.append(msg["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return bodies


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendMessageBatch with one entry whose DelaySeconds exceeds 900 fails only that entry
    (InvalidParameterValue, SenderFault) while its two valid siblings still enqueue.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    drain_s = 12

    entries = [
        {"Id": "before", "MessageBody": "kept-before"},
        {"Id": "baddelay", "MessageBody": "rejected-delay", "DelaySeconds": 901},
        {"Id": "after", "MessageBody": "kept-after"},
    ]
    resp = sqs.send_message_batch(QueueUrl=url, Entries=entries)
    succ = {e["Id"]: e for e in resp.get("Successful", [])}
    fail = {e["Id"]: e for e in resp.get("Failed", [])}

    assert set(succ) == {"before", "after"}, f"Successful Ids: {sorted(succ)}"
    assert set(fail) == {"baddelay"}, f"Failed Ids: {sorted(fail)}"

    bad = fail["baddelay"]
    assert bad.get("Code") == ERR_INVALID_PARAMETER, f"Failed Code: {bad.get('Code')!r}"
    assert bad.get("SenderFault") is True, (
        f"SenderFault must be True for an out-of-range DelaySeconds, got {bad.get('SenderFault')!r}"
    )

    # An independent receive proves the siblings landed and the oversized entry did not
    # sneak in under a different id.
    bodies = _drain(sqs, url, timeout_s=drain_s)
    assert set(bodies) == {"kept-before", "kept-after"}, (
        f"expected exactly the two valid bodies enqueued, drained {bodies}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
