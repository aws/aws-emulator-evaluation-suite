"""change-message-visibility-batch-partial-failure."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "change-message-visibility-batch-partial-failure"
GROUP = "batch"
SERVICES = ["sqs"]


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ChangeMessageVisibilityBatch fails a malformed-handle entry on its own, leaving that message on
    its original timeout, while the valid sibling entry's extension takes effect.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-sqs-batch-cvt-"),
        Attributes={"VisibilityTimeout": "4"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    sqs.send_message(QueueUrl=url, MessageBody="cvt-batch-good")
    sqs.send_message(QueueUrl=url, MessageBody="cvt-batch-bad")

    handles = {}
    deadline = time.monotonic() + 20.0
    while len(handles) < 2 and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=3)
        for msg in resp.get("Messages", []):
            handles[msg["Body"]] = msg["ReceiptHandle"]
    assert set(handles.keys()) == {"cvt-batch-good", "cvt-batch-bad"}, (
        f"expected both messages received, got {sorted(handles.keys())}"
    )

    resp = sqs.change_message_visibility_batch(
        QueueUrl=url,
        Entries=[
            {"Id": "good", "ReceiptHandle": handles["cvt-batch-good"], "VisibilityTimeout": 20},
            {"Id": "bad", "ReceiptHandle": "not-a-valid-handle", "VisibilityTimeout": 20},
        ],
    )
    successful_ids = {e["Id"] for e in resp.get("Successful", [])}
    failed = {e["Id"]: e for e in resp.get("Failed", [])}
    assert successful_ids == {"good"}, f"expected only 'good' to succeed, got {successful_ids}"
    assert set(failed.keys()) == {"bad"}, f"expected only 'bad' to fail, got {set(failed.keys())}"
    assert failed["bad"]["Code"] == "ReceiptHandleIsInvalid", (
        f"expected ReceiptHandleIsInvalid, got {failed['bad']['Code']}"
    )
    assert failed["bad"].get("Message") == "The input receipt handle is invalid.", (
        f"expected message 'The input receipt handle is invalid.', got {failed['bad'].get('Message')!r}"
    )

    # Past the original 4s timeout but before the 20s extension: only "bad" (whose extension
    # failed) should reappear while "good" stays hidden.
    deadline = time.monotonic() + 15.0
    found_bad = False
    while time.monotonic() < deadline and not found_bad:
        r = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=3)
        for msg in r.get("Messages", []):
            assert msg["Body"] != "cvt-batch-good", "extended message reappeared before its new timeout"
            if msg["Body"] == "cvt-batch-bad":
                found_bad = True
                sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    assert found_bad, "message whose visibility-extension failed never reappeared on schedule"

    # The successfully extended message reappears once its 20s window elapses.
    deadline = time.monotonic() + 25.0
    good_seen = False
    while time.monotonic() < deadline and not good_seen:
        r = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=3)
        for msg in r.get("Messages", []):
            if msg["Body"] == "cvt-batch-good":
                good_seen = True
                sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    assert good_seen, "successfully extended message never reappeared after its extension elapsed"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
