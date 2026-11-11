"""delete-message-repeated-with-the-same-receipt-handle-succeeds."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-message-repeated-with-the-same-receipt-handle-succeeds"
GROUP = 'delete-semantics'
SERVICES = ['sqs']

_SCENARIO = "sqs-repeated-delete"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A repeated DeleteMessage and a DeleteMessageBatch entry with an already-used receipt handle
    both succeed and the message never returns, while an undeleted sibling reappears after its
    short visibility timeout, proving the window passed.
    """
    sqs = ctx.client("sqs")
    url = _create_queue(ctx, {"VisibilityTimeout": "3"})
    sqs.send_message(QueueUrl=url, MessageBody="sim2real-delete-me")
    sqs.send_message(QueueUrl=url, MessageBody="sim2real-keep-me")

    handles: dict[str, str] = {}
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline and len(handles) < 2:
        for msg in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                       WaitTimeSeconds=2).get("Messages", []):
            handles[msg["Body"]] = msg["ReceiptHandle"]
    assert sorted(handles) == ["sim2real-delete-me", "sim2real-keep-me"], (
        f"both messages must be received once, got {sorted(handles)!r}")

    handle = handles["sim2real-delete-me"]
    sqs.delete_message(QueueUrl=url, ReceiptHandle=handle)
    sqs.delete_message(QueueUrl=url, ReceiptHandle=handle)
    batch = sqs.delete_message_batch(QueueUrl=url, Entries=[{"Id": "again", "ReceiptHandle": handle}])
    assert ([e["Id"] for e in batch.get("Successful", [])], batch.get("Failed", [])) == (["again"], []), (
        f"a DeleteMessageBatch entry for an already-deleted message must be Successful, got "
        f"Successful={batch.get('Successful')!r} Failed={batch.get('Failed')!r}")

    seen: list[str] = []
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline and "sim2real-keep-me" not in seen:
        for msg in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                       WaitTimeSeconds=2).get("Messages", []):
            seen.append(msg["Body"])
            if msg["Body"] == "sim2real-keep-me":
                sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    assert "sim2real-keep-me" in seen, (
        "the undeleted sibling never reappeared after its 3s visibility timeout")
    assert "sim2real-delete-me" not in seen, "the deleted message was delivered again"
    leftover = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5,
                                   VisibilityTimeout=0).get("Messages", [])
    assert [m["Body"] for m in leftover] == [], (
        f"the queue must be empty once the sibling is deleted, got {[m['Body'] for m in leftover]!r}")



def _error(fn) -> tuple[str, str]:
    """The (Code, Message) of the ClientError ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_queue(ctx, attributes=None) -> str:
    """CreateQueue (tagged + prefix-named) and register DeleteQueue immediately."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-sqs-"), Attributes=attributes or {},
        tags={"sim2real": _SCENARIO, "sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda u=url: sqs.delete_queue(QueueUrl=u))
    return url


def _receive_all(ctx, url: str, wanted: set[str], timeout_s: float = 60.0, **kwargs) -> dict:
    """Receive (and delete) until every body in ``wanted`` has been seen; body -> message for
    EVERY message seen on the way."""
    sqs = ctx.client("sqs")
    seen: dict = {}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and not wanted <= set(seen):
        for msg in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2,
                                       **kwargs).get("Messages", []):
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
            seen[msg["Body"]] = msg
    missing = sorted(wanted - set(seen))
    assert not missing, (
        f"within {timeout_s}s the queue never delivered {missing!r}; it delivered {sorted(seen)!r}")
    return seen


def _receive_window(ctx, url: str, window_s: float) -> dict:
    """Receive (and delete) everything delivered within ``window_s``; body -> message."""
    sqs = ctx.client("sqs")
    seen: dict = {}
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        for msg in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                       WaitTimeSeconds=1).get("Messages", []):
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
            seen[msg["Body"]] = msg
    return seen


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
