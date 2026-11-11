"""fifo-send-without-message-group-id-rejected-and-group-stream-unchanged."""
from __future__ import annotations

import collections
import time

from behavioral_harness import tags

CHECK = "fifo-send-without-message-group-id-rejected-and-group-stream-unchanged"
GROUP = 'fifo'
SERVICES = ['sqs']

GROUPS = ["g0", "g1", "g2", "g3"]
PER_GROUP = 5
TOTAL = len(GROUPS) * PER_GROUP


class _UnexpectedSuccess(Exception):
    """Raised when a call AWS rejects is accepted."""


def _error_code(fn, **kwargs) -> dict:
    """The AWS error response (Error + ResponseMetadata), or a raise. Never a falsy sentinel."""
    try:
        resp = fn(**kwargs)
    except Exception as exc:  # noqa: BLE001 — the code is the assertion
        response = getattr(exc, "response", {})
        if not response.get("Error", {}).get("Code"):
            raise AssertionError(f"call raised {type(exc).__name__} with no AWS error code: {exc}") from exc
        return response
    raise _UnexpectedSuccess(f"the call was ACCEPTED and returned {resp!r}")


def _await_visible(sqs, url: str, want: int) -> str:
    """Poll ApproximateNumberOfMessages until it reads `want`, else fail with what we saw."""
    seen = ""
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        seen = sqs.get_queue_attributes(
            QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"],
        )["Attributes"]["ApproximateNumberOfMessages"]
        if seen == str(want):
            return seen
        time.sleep(2)
    raise AssertionError(f"queue never reported {want} visible messages; last read {seen!r}")


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A FIFO send with no MessageGroupId is rejected (MissingParameter) and enqueues nothing.

    The queued messages still drain in per-group order, and a valid follow-up send lands next.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-d5-") + ".fifo",
        Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true",
                    "VisibilityTimeout": "120", "ReceiveMessageWaitTimeSeconds": "0"},
        tags={"sim2real-check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    # Interleaved so per-group order differs from send order.
    for i in range(TOTAL):
        group = GROUPS[i % len(GROUPS)]
        sqs.send_message(QueueUrl=url, MessageBody=f"{group}|{i // len(GROUPS)}",
                         MessageGroupId=group)
    _await_visible(sqs, url, TOTAL)

    rejected_body = "orphan|no-group"
    response = _error_code(sqs.send_message, QueueUrl=url, MessageBody=rejected_body)
    code = response["Error"]["Code"]
    assert code == "MissingParameter", (
        f"a FIFO SendMessage with no MessageGroupId was rejected with {code!r}, "
        f"expected 'MissingParameter'"
    )
    status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert isinstance(status, int) and 400 <= status < 500, f"the group-less send was rejected with HTTP {status!r}, expected 4xx"
    message = response["Error"].get("Message") or ""
    assert message.strip(), "expected a non-empty MissingParameter message"

    _await_visible(sqs, url, TOTAL)

    control_body = f"{GROUPS[0]}|{PER_GROUP}"
    sent = sqs.send_message(QueueUrl=url, MessageBody=control_body, MessageGroupId=GROUPS[0])
    assert sent["SequenceNumber"], f"the control send returned no SequenceNumber: {sent!r}"
    _await_visible(sqs, url, TOTAL + 1)

    drained: list[tuple[str, str]] = []
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline and len(drained) < TOTAL + 1:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5,
                                   MessageSystemAttributeNames=["MessageGroupId"])
        msgs = resp.get("Messages", [])
        if not msgs:
            continue
        for m in msgs:
            drained.append((m["Body"], m["Attributes"]["MessageGroupId"]))
        sqs.delete_message_batch(QueueUrl=url, Entries=[
            {"Id": f"d{i}", "ReceiptHandle": m["ReceiptHandle"]} for i, m in enumerate(msgs)])

    bodies = [b for b, _g in drained]
    assert rejected_body not in bodies, (
        f"the rejected group-less message was delivered anyway, as {dict(drained)[rejected_body]!r}"
    )
    assert control_body in bodies, f"the control message never arrived; drained {sorted(bodies)!r}"
    assert len(bodies) == TOTAL + 1, (
        f"drained {len(bodies)} messages, expected {TOTAL + 1} "
        f"({TOTAL} setup + 1 control, 0 from the rejected send): {sorted(bodies)!r}"
    )

    per_group: dict[str, list[int]] = collections.defaultdict(list)
    for body, group in drained:
        body_group, ordinal = body.split("|")
        assert body_group == group, (
            f"message {body!r} carried MessageGroupId {group!r}, not its own group"
        )
        per_group[group].append(int(ordinal))
    expected = {g: list(range(PER_GROUP + (1 if g == GROUPS[0] else 0))) for g in GROUPS}
    assert dict(per_group) == expected, (
        f"per-group order after the rejection is {dict(per_group)!r}, expected {expected!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
