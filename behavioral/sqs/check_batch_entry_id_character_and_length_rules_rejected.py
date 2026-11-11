"""batch-entry-id-character-and-length-rules-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-entry-id-character-and-length-rules-rejected"
GROUP = "limits"
SERVICES = ["sqs"]

_TAGS = {"sim2real": "batch-entry-id-character-and-length-rules-rejected"}
_BAD_ID = "AWS.SimpleQueueService.InvalidBatchEntryId"
_BAD_ID_MSG = ("A batch entry id can only contain alphanumeric characters, hyphens and "
               "underscores. It can be at most 80 letters long.")
_ID_80 = "Az09-_" + "x" * 74


def _error(fn) -> dict:
    """The botocore Error dict ``fn`` raises. An unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the batch to be refused, but it succeeded: {result!r}")


def _receive_all(sqs, url: str, want: int, visibility: int = 120) -> list[dict]:
    got: dict[str, dict] = {}
    deadline = time.monotonic() + 30
    while len(got) < want and time.monotonic() < deadline:
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2,
                                     VisibilityTimeout=visibility).get("Messages", []):
            got[m["MessageId"]] = m
    return list(got.values())


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Batch entry Ids outside 1-80 alphanumeric/hyphen/underscore chars get InvalidBatchEntryId on
    all three batch ops, request-wide with no partial effect; a valid 80-char Id is accepted.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-batchid-"), tags=_TAGS)[
        "QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    refused_body = ctx.unique_name("refused-")
    for bad in ("a.b", "a b", "", "a" * 81):
        err = _error(lambda bad=bad: sqs.send_message_batch(QueueUrl=url, Entries=[
            {"Id": bad, "MessageBody": refused_body}, {"Id": "ok", "MessageBody": refused_body}]))
        assert (err.get("Code"), err.get("Message")) == (_BAD_ID, _BAD_ID_MSG), (
            f"SendMessageBatch with entry Id {bad!r} ({len(bad)} chars) answered {err!r}"
        )
    stray = _receive_all(sqs, url, 1)
    assert stray == [], (
        f"refused SendMessageBatch requests enqueued {len(stray)} message(s); the valid sibling "
        f"entry must not be sent when another entry's Id is invalid"
    )

    sent = sqs.send_message_batch(QueueUrl=url, Entries=[
        {"Id": _ID_80, "MessageBody": "kept"}])
    assert [e["Id"] for e in sent.get("Successful", [])] == [_ID_80], (
        f"SendMessageBatch with an 80-character Id answered {sent!r}"
    )
    held = _receive_all(sqs, url, 1)
    assert [m["Body"] for m in held] == ["kept"], f"received {[m['Body'] for m in held]!r}"
    handle = held[0]["ReceiptHandle"]

    err = _error(lambda: sqs.change_message_visibility_batch(QueueUrl=url, Entries=[
        {"Id": "a b", "ReceiptHandle": handle, "VisibilityTimeout": 0}]))
    assert (err.get("Code"), err.get("Message")) == (_BAD_ID, _BAD_ID_MSG), (
        f"ChangeMessageVisibilityBatch with Id 'a b' answered {err!r}"
    )
    err = _error(lambda: sqs.delete_message_batch(QueueUrl=url, Entries=[
        {"Id": "a" * 81, "ReceiptHandle": handle}]))
    assert (err.get("Code"), err.get("Message")) == (_BAD_ID, _BAD_ID_MSG), (
        f"DeleteMessageBatch with an 81-character Id answered {err!r}"
    )
    early = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=3)
    assert early.get("Messages", []) == [], (
        "the refused visibility batch (VisibilityTimeout 0) released the message anyway"
    )

    # Positive control: the same handle, under an 80-character Id, releases the message, which
    # comes back -- so the refused delete deleted nothing -- and a valid delete removes it.
    resp = sqs.change_message_visibility_batch(QueueUrl=url, Entries=[
        {"Id": _ID_80, "ReceiptHandle": handle, "VisibilityTimeout": 0}])
    assert [e["Id"] for e in resp.get("Successful", [])] == [_ID_80], (
        f"ChangeMessageVisibilityBatch with an 80-character Id answered {resp!r}"
    )
    back = _receive_all(sqs, url, 1)
    assert [m["Body"] for m in back] == ["kept"], (
        f"after the refused delete and a valid release the queue delivered "
        f"{[m['Body'] for m in back]!r}; the refused DeleteMessageBatch must not delete"
    )
    resp = sqs.delete_message_batch(QueueUrl=url, Entries=[
        {"Id": _ID_80, "ReceiptHandle": back[0]["ReceiptHandle"]}])
    assert [e["Id"] for e in resp.get("Successful", [])] == [_ID_80], (
        f"DeleteMessageBatch with an 80-character Id answered {resp!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
