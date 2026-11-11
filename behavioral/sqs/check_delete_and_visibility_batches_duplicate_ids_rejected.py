"""delete-and-visibility-batches-duplicate-ids-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-and-visibility-batches-duplicate-ids-rejected"
GROUP = "limits"
SERVICES = ["sqs"]

_TAGS = {"sim2real": "delete-and-visibility-batches-duplicate-ids-rejected"}
_NOT_DISTINCT = "AWS.SimpleQueueService.BatchEntryIdsNotDistinct"
_NOT_DISTINCT_MSG = "Id dup repeated."


def _error(fn) -> dict:
    """The botocore Error dict ``fn`` raises. An unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the batch to be refused, but it succeeded: {result!r}")


def _take(sqs, url: str, n: int, *, timeout_s=30) -> list[dict]:
    held: dict[str, dict] = {}
    deadline = time.monotonic() + timeout_s
    while len(held) < n and time.monotonic() < deadline:
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2,
                                     VisibilityTimeout=120).get("Messages", []):
            held[m["MessageId"]] = m
    return list(held.values())


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """DeleteMessageBatch and ChangeMessageVisibilityBatch with two entries sharing an Id are
    refused wholesale with BatchEntryIdsNotDistinct, touching neither message; distinct Ids succeed
    in full.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-batchdup-"),
        Attributes={"VisibilityTimeout": "120"}, tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    sqs.send_message_batch(QueueUrl=url, Entries=[
        {"Id": "s0", "MessageBody": "dup-msg-a"},
        {"Id": "s1", "MessageBody": "dup-msg-b"},
    ])
    held = _take(sqs, url, 2)
    assert len(held) == 2, f"could take only {len(held)} of 2 messages in flight"
    by_body = {m["Body"]: m for m in held}
    handle_a = by_body["dup-msg-a"]["ReceiptHandle"]
    handle_b = by_body["dup-msg-b"]["ReceiptHandle"]

    err = _error(lambda: sqs.delete_message_batch(QueueUrl=url, Entries=[
        {"Id": "dup", "ReceiptHandle": handle_a},
        {"Id": "dup", "ReceiptHandle": handle_b},
    ]))
    assert (err.get("Code"), err.get("Message")) == (_NOT_DISTINCT, _NOT_DISTINCT_MSG), (
        f"a duplicate-Id DeleteMessageBatch answered {err!r}"
    )

    err = _error(lambda: sqs.change_message_visibility_batch(QueueUrl=url, Entries=[
        {"Id": "dup", "ReceiptHandle": handle_a, "VisibilityTimeout": 0},
        {"Id": "dup", "ReceiptHandle": handle_b, "VisibilityTimeout": 0},
    ]))
    assert (err.get("Code"), err.get("Message")) == (_NOT_DISTINCT, _NOT_DISTINCT_MSG), (
        f"a duplicate-Id ChangeMessageVisibilityBatch answered {err!r}"
    )

    # Both messages are still in flight, so an immediate receive sees nothing.
    leaked = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=3)
    assert leaked.get("Messages", []) == [], (
        f"after the two refused duplicate-Id batches a receive returned "
        f"{[m['Body'] for m in leaked.get('Messages', [])]!r}; the refusals must not have "
        f"deleted or released either message"
    )

    resp = sqs.change_message_visibility_batch(QueueUrl=url, Entries=[
        {"Id": "v0", "ReceiptHandle": handle_a, "VisibilityTimeout": 0},
        {"Id": "v1", "ReceiptHandle": handle_b, "VisibilityTimeout": 0},
    ])
    ok = {e["Id"] for e in resp.get("Successful", [])}
    assert ok == {"v0", "v1"} and not resp.get("Failed"), (
        f"a distinct-Id ChangeMessageVisibilityBatch answered Successful={resp.get('Successful')!r} "
        f"Failed={resp.get('Failed')!r}"
    )
    released = _take(sqs, url, 2)
    released_bodies = {m["Body"] for m in released}
    assert released_bodies == {"dup-msg-a", "dup-msg-b"}, (
        f"after the distinct-Id visibility batch, {sorted(released_bodies)} came back; "
        f"expected both released messages"
    )

    # The release minted fresh receipt handles; delete with those.
    by_body2 = {m["Body"]: m for m in released}
    resp = sqs.delete_message_batch(QueueUrl=url, Entries=[
        {"Id": "d0", "ReceiptHandle": by_body2["dup-msg-a"]["ReceiptHandle"]},
        {"Id": "d1", "ReceiptHandle": by_body2["dup-msg-b"]["ReceiptHandle"]},
    ])
    ok = {e["Id"] for e in resp.get("Successful", [])}
    assert ok == {"d0", "d1"} and not resp.get("Failed"), (
        f"a distinct-Id DeleteMessageBatch answered Successful={resp.get('Successful')!r} "
        f"Failed={resp.get('Failed')!r}"
    )
    empty = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=3)
    assert empty.get("Messages", []) == [], (
        f"after both deletes a receive returned {[m['Body'] for m in empty.get('Messages', [])]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
