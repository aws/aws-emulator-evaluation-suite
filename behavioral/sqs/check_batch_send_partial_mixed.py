"""batch-send-partial-mixed."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-send-partial-mixed"
GROUP = 'errors'
SERVICES = ['sqs']

ERR_BATCH_EMPTY_VALUE = "EmptyValue"

@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendMessageBatch with one valid and one empty-body entry succeeds for the valid one,
    which is then received, and fails the empty one with EmptyValue "No Value Found for
    SendMessageBatchRequestEntry.2.MessageBody."."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    entries = [
        {"Id": "ok", "MessageBody": "valid-body"},
        {"Id": "empty", "MessageBody": ""},
    ]
    resp = sqs.send_message_batch(QueueUrl=url, Entries=entries)
    successful = {e["Id"] for e in resp.get("Successful", [])}
    failed = {e["Id"]: e for e in resp.get("Failed", [])}
    if successful != {"ok"}:
        raise AssertionError(f"expected only 'ok' successful, got {sorted(successful)}")
    if set(failed) != {"empty"}:
        raise AssertionError(f"expected only 'empty' failed, got {sorted(failed)}")
    if failed["empty"].get("Code") != ERR_BATCH_EMPTY_VALUE:
        raise AssertionError(
            f"expected Failed code {ERR_BATCH_EMPTY_VALUE}, got {failed['empty'].get('Code')!r}"
        )
    expected = "No Value Found for SendMessageBatchRequestEntry.2.MessageBody."
    if failed["empty"].get("Message") != expected:
        raise AssertionError(f"expected Failed message {expected!r}, got {failed['empty'].get('Message')!r}")

    # The valid entry must actually be enqueued (the failed sibling did not poison the batch) —
    # proved by an independent read at the destination, not by the send response alone.
    good_message_id = resp["Successful"][0]["MessageId"]
    received = sqs.receive_message(
        QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=10
    ).get("Messages", [])
    match = next((m for m in received if m["MessageId"] == good_message_id), None)
    if match is None:
        raise AssertionError(
            f"expected message {good_message_id} (entry 'ok') to be receivable from the queue, "
            f"got {[m.get('MessageId') for m in received]}"
        )
    if match["Body"] != "valid-body":
        raise AssertionError(f"expected received body 'valid-body', got {match['Body']!r}")
    sqs.delete_message(QueueUrl=url, ReceiptHandle=match["ReceiptHandle"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
