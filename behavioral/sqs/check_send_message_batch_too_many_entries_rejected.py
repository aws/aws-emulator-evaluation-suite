"""send-message-batch-too-many-entries-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-message-batch-too-many-entries-rejected"
GROUP = "overly-permissive"
SERVICES = ["sqs"]

_TAGS = {"sim2real:managed": "true", "sim2real": "send-message-batch-too-many-entries-rejected"}


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendMessageBatch with more than the 10-entry maximum is rejected wholesale with
    TooManyEntriesInBatchRequest (none of the 11 messages land), while a batch at the
    10-entry limit succeeds in full."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-sqs-batch-limit-"), tags=_TAGS
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    oversized_entries = [{"Id": f"m{i}", "MessageBody": f"body-{i}"} for i in range(11)]
    code, message = _error(lambda: sqs.send_message_batch(QueueUrl=url, Entries=oversized_entries))
    # empirically, real AWS returns the wire error code prefixed with the service
    # namespace: "AWS.SimpleQueueService.TooManyEntriesInBatchRequest".
    assert code == "AWS.SimpleQueueService.TooManyEntriesInBatchRequest", (
        f"expected AWS.SimpleQueueService.TooManyEntriesInBatchRequest, got {code!r}"
    )
    assert message == "Maximum number of entries per request are 10. You have sent 11.", (
        f"unexpected refusal message {message!r}"
    )

    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
    assert not resp.get("Messages"), "messages were enqueued despite the rejected oversized batch"

    # positive control: exactly 10 entries is within the limit and succeeds in full
    valid_entries = [{"Id": f"ok{i}", "MessageBody": f"ok-body-{i}"} for i in range(10)]
    resp = sqs.send_message_batch(QueueUrl=url, Entries=valid_entries)
    assert len(resp.get("Successful", [])) == 10, (
        f"expected all 10 valid entries to succeed, got {resp.get('Successful')!r}"
    )
    assert not resp.get("Failed"), f"valid 10-entry batch reported failures: {resp.get('Failed')!r}"

    delivered = 0
    deadline = time.monotonic() + 20.0
    while delivered < 10 and time.monotonic() < deadline:
        r = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=3)
        for msg in r.get("Messages", []):
            delivered += 1
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    assert delivered == 10, f"expected 10 delivered messages from the valid batch, got {delivered}"


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
