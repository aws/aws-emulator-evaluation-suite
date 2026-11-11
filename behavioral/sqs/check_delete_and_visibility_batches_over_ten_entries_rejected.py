"""delete-and-visibility-batches-over-ten-entries-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-and-visibility-batches-over-ten-entries-rejected"
GROUP = "limits"
SERVICES = ["sqs"]

_TAGS = {"sim2real": "delete-and-visibility-batches-over-ten-entries-rejected"}
_TOO_MANY = "AWS.SimpleQueueService.TooManyEntriesInBatchRequest"
_TOO_MANY_MSG = "Maximum number of entries per request are 10. You have sent 11."
_EMPTY = "AWS.SimpleQueueService.EmptyBatchRequest"
_EMPTY_CMV_MSG = "There should be at least one ChangeMessageVisibilityBatchRequestEntry in the request."


def _error(fn) -> dict:
    """The botocore Error dict ``fn`` raises. An unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the batch to be refused, but it succeeded: {result!r}")


def _take(sqs, url: str, n: int) -> list[dict]:
    held: dict[str, dict] = {}
    deadline = time.monotonic() + 45
    while len(held) < n and time.monotonic() < deadline:
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2,
                                     VisibilityTimeout=120).get("Messages", []):
            held[m["MessageId"]] = m
    return list(held.values())


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """DeleteMessageBatch and ChangeMessageVisibilityBatch refuse 11 entries with
    TooManyEntriesInBatchRequest and act on none; an empty visibility batch is EmptyBatchRequest;
    10-entry batches succeed, so released messages return and deleted ones stay gone.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-batch11-"),
        Attributes={"VisibilityTimeout": "120"}, tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    for chunk in range(3):
        sqs.send_message_batch(QueueUrl=url, Entries=[
            {"Id": f"m{k}", "MessageBody": f"msg-{chunk}-{k}"} for k in range(7)])
    held = _take(sqs, url, 21)
    assert len(held) == 21, f"could take only {len(held)} of 21 messages in flight"
    first11, rest = held[:11], held[11:]

    err = _error(lambda: sqs.delete_message_batch(QueueUrl=url, Entries=[
        {"Id": f"d{i}", "ReceiptHandle": m["ReceiptHandle"]} for i, m in enumerate(first11)]))
    assert (err.get("Code"), err.get("Message")) == (_TOO_MANY, _TOO_MANY_MSG), (
        f"an 11-entry DeleteMessageBatch answered {err!r}"
    )
    err = _error(lambda: sqs.change_message_visibility_batch(QueueUrl=url, Entries=[
        {"Id": f"v{i}", "ReceiptHandle": m["ReceiptHandle"], "VisibilityTimeout": 0}
        for i, m in enumerate(first11)]))
    assert (err.get("Code"), err.get("Message")) == (_TOO_MANY, _TOO_MANY_MSG), (
        f"an 11-entry ChangeMessageVisibilityBatch answered {err!r}"
    )
    err = _error(lambda: sqs.change_message_visibility_batch(QueueUrl=url, Entries=[]))
    assert (err.get("Code"), err.get("Message")) == (_EMPTY, _EMPTY_CMV_MSG), (
        f"an empty ChangeMessageVisibilityBatch answered {err!r}"
    )

    # All 21 are still in flight, so an immediate receive sees nothing.
    leaked = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=3)
    assert leaked.get("Messages", []) == [], (
        f"after refused batches a receive returned {[m['Body'] for m in leaked['Messages']]!r}; "
        f"the refused 11-entry visibility batch released messages"
    )

    # The first 11 handles still being valid shows the refused delete deleted none of them.
    to_delete, to_release = first11[:10], rest[:10]
    resp = sqs.delete_message_batch(QueueUrl=url, Entries=[
        {"Id": f"d{i}", "ReceiptHandle": m["ReceiptHandle"]} for i, m in enumerate(to_delete)])
    assert len(resp.get("Successful", [])) == 10 and not resp.get("Failed"), (
        f"a 10-entry DeleteMessageBatch answered {resp.get('Failed')!r}"
    )
    resp = sqs.change_message_visibility_batch(QueueUrl=url, Entries=[
        {"Id": f"v{i}", "ReceiptHandle": m["ReceiptHandle"], "VisibilityTimeout": 0}
        for i, m in enumerate(to_release)])
    assert len(resp.get("Successful", [])) == 10 and not resp.get("Failed"), (
        f"a 10-entry ChangeMessageVisibilityBatch answered {resp.get('Failed')!r}"
    )
    again = {m["MessageId"] for m in _take(sqs, url, 10)}
    assert again == {m["MessageId"] for m in to_release}, (
        f"after releasing ten messages, {len(again)} were received again and "
        f"{len(again & {m['MessageId'] for m in to_delete})} of them were among the deleted ten"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
