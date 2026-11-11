"""change-message-visibility-batch-repeated-receipt-handle-last-entry-wins."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "change-message-visibility-batch-repeated-receipt-handle-last-entry-wins"
GROUP = "batch"
SERVICES = ["sqs"]

_TAGS = {"sim2real": "change-message-visibility-batch-repeated-receipt-handle-last-entry-wins"}


def _receive_one(sqs, url, *, visibility_timeout, timeout_s=20.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2,
            VisibilityTimeout=visibility_timeout,
        ).get("Messages", [])
        if msgs:
            return msgs[0]
    raise AssertionError(f"no message receivable within {timeout_s}s")


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ChangeMessageVisibilityBatch entries naming the same receipt handle under distinct Ids both
    succeed with no Failed, in either order; which timeout takes effect is not graded because the
    docs do not say in what order entries apply.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-cmvdup-"),
        Attributes={"VisibilityTimeout": "20"}, tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    for leg, order in (("leg1", ("extend", "release")), ("leg2", ("release", "extend"))):
        body = f"cmvdup-{leg}"
        sqs.send_message(QueueUrl=url, MessageBody=body)
        msg = _receive_one(sqs, url, visibility_timeout=20)
        assert msg["Body"] == body, f"receive got {msg['Body']!r}, expected {body!r}"
        handle = msg["ReceiptHandle"]
        timeouts = {"extend": 60, "release": 0}
        resp = sqs.change_message_visibility_batch(QueueUrl=url, Entries=[
            {"Id": entry_id, "ReceiptHandle": handle, "VisibilityTimeout": timeouts[entry_id]}
            for entry_id in order
        ])
        ok = {e["Id"] for e in resp.get("Successful", [])}
        assert ok == {"extend", "release"} and not resp.get("Failed"), (
            f"{leg}: a batch with two Ids sharing one receipt handle answered "
            f"Successful={resp.get('Successful')!r} Failed={resp.get('Failed')!r}"
        )
        # Delete the message so the next leg receives its own message, not this one.
        sqs.delete_message(QueueUrl=url, ReceiptHandle=handle)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
