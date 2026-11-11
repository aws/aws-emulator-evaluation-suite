"""send-message-batch-delay-seconds-applies-to-each-entry-alone."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-message-batch-delay-seconds-applies-to-each-entry-alone"
GROUP = 'delay'
SERVICES = ['sqs']

_SCENARIO = "sqs-batch-entry-delay"

_DELAY = 8


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """In one SendMessageBatch each entry's DelaySeconds governs only that entry: the undelayed
    entry arrives on an earlier receive, the 8-second one not before 8 seconds after the send,
    and each keeps its own MessageAttributes."""
    sqs = ctx.client("sqs")
    url = _create_queue(ctx)
    sent_at = time.monotonic()
    resp = sqs.send_message_batch(QueueUrl=url, Entries=[
        {"Id": "now", "MessageBody": "sim2real-now",
         "MessageAttributes": {"slot": {"DataType": "String", "StringValue": "immediate"}}},
        {"Id": "later", "MessageBody": "sim2real-later", "DelaySeconds": _DELAY,
         "MessageAttributes": {"slot": {"DataType": "String", "StringValue": "delayed"}}},
    ])
    assert sorted(e["Id"] for e in resp.get("Successful", [])) == ["later", "now"] \
        and not resp.get("Failed"), f"both entries must be accepted, got {resp.get('Failed')!r}"

    arrivals: dict[str, tuple[int, float, str]] = {}
    call = 0
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline and len(arrivals) < 2:
        call += 1
        for msg in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1,
                                       MessageAttributeNames=["All"]).get("Messages", []):
            arrivals[msg["Body"]] = (call, time.monotonic() - sent_at,
                                     msg["MessageAttributes"]["slot"]["StringValue"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    assert sorted(arrivals) == ["sim2real-later", "sim2real-now"], (
        f"both entries must eventually be delivered, got {sorted(arrivals)!r}")
    now_call, _, now_slot = arrivals["sim2real-now"]
    later_call, later_at, later_slot = arrivals["sim2real-later"]
    assert (now_slot, later_slot) == ("immediate", "delayed"), (
        f"each entry must keep its own attributes, got {now_slot!r} and {later_slot!r}")
    assert now_call < later_call, (
        f"the undelayed entry must be handed out by an earlier receive than the delayed one; "
        f"they arrived on receive #{now_call} and #{later_call}, so the delay held both back")
    assert later_at >= _DELAY, (
        f"the entry with DelaySeconds={_DELAY} was delivered {later_at:.1f}s after the send")


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
