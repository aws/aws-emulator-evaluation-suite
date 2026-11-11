"""duplicate-batch-ids."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-batch-ids"
GROUP = 'errors'
SERVICES = ['sqs']

ERR_BATCH_IDS_NOT_DISTINCT = "AWS.SimpleQueueService.BatchEntryIdsNotDistinct"
MSG_BATCH_IDS_NOT_DISTINCT = "Id dup repeated."


def _client_error(fn):
    """The botocore Error dict of a rejected call; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendMessageBatch with duplicate entry Ids is rejected wholesale with
    BatchEntryIdsNotDistinct, none of the duplicate-Id entries enqueue, and an
    otherwise-identical batch with distinct Ids on the same queue succeeds in full."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    dup_entries = [
        {"Id": "dup", "MessageBody": "first"},
        {"Id": "dup", "MessageBody": "second"},
    ]
    error = _client_error(lambda: sqs.send_message_batch(QueueUrl=url, Entries=dup_entries))
    assert error.get("Code") == ERR_BATCH_IDS_NOT_DISTINCT, (
        f"expected {ERR_BATCH_IDS_NOT_DISTINCT}, got {error.get('Code')!r}"
    )
    assert error.get("Message") == MSG_BATCH_IDS_NOT_DISTINCT, (
        f"expected message {MSG_BATCH_IDS_NOT_DISTINCT!r}, got {error.get('Message')!r}"
    )

    # effect absent: the wholesale rejection must not have enqueued either entry
    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
    assert not resp.get("Messages"), (
        f"messages were enqueued despite the rejected duplicate-Id batch: {resp.get('Messages')}"
    )

    # positive control: the identical bodies with distinct Ids on the same queue succeed in full
    distinct_entries = [
        {"Id": "one", "MessageBody": "first"},
        {"Id": "two", "MessageBody": "second"},
    ]
    resp = sqs.send_message_batch(QueueUrl=url, Entries=distinct_entries)
    assert len(resp.get("Successful", [])) == 2, f"expected 2 successes, got {resp}"
    assert not resp.get("Failed"), f"unexpected per-entry failures: {resp.get('Failed')}"

    delivered = []
    deadline = time.monotonic() + 20.0
    while len(delivered) < 2 and time.monotonic() < deadline:
        r = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=3)
        for msg in r.get("Messages", []):
            delivered.append(msg["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    assert sorted(delivered) == ["first", "second"], (
        f"expected both distinct-Id messages delivered, got {delivered}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
