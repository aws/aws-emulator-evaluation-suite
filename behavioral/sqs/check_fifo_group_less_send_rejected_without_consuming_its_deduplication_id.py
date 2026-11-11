"""fifo-group-less-send-rejected-without-consuming-its-deduplication-id."""

from __future__ import annotations

import collections
import time

from behavioral_harness import tags

CHECK = "fifo-group-less-send-rejected-without-consuming-its-deduplication-id"
GROUP = "fifo"
SERVICES = ["sqs"]

# Unequal group lengths, interleaved, so per-group order differs from send order.
SENDS = [
    ("alpha", 0),
    ("beta", 0),
    ("beta", 1),
    ("gamma", 0),
    ("beta", 2),
    ("alpha", 1),
    ("beta", 3),
]
REUSED_DEDUP_ID = "dedup-reused-by-the-rejected-send"
MISSING_GROUP_MSG = "The request must contain the parameter MessageGroupId."


class _UnexpectedSuccess(Exception):
    """Raised when a call AWS rejects is accepted."""


def _error_code(fn, **kwargs) -> dict:
    """The AWS error response (Error + ResponseMetadata), or a raise. Never a falsy sentinel."""
    try:
        resp = fn(**kwargs)
    except Exception as exc:  # noqa: BLE001 — the code is the assertion
        response = getattr(exc, "response", {})
        if not response.get("Error", {}).get("Code"):
            raise AssertionError(
                f"call raised {type(exc).__name__} with no AWS error code: {exc}"
            ) from exc
        return response
    raise _UnexpectedSuccess(f"the call was ACCEPTED and returned {resp!r}")


def _await_visible(sqs, url: str, want: int) -> str:
    """Poll ApproximateNumberOfMessages until it reads `want`, else fail with what we saw."""
    seen = ""
    deadline = time.monotonic() + 40.0
    while time.monotonic() < deadline:
        seen = sqs.get_queue_attributes(
            QueueUrl=url,
            AttributeNames=["ApproximateNumberOfMessages"],
        )["Attributes"]["ApproximateNumberOfMessages"]
        if seen == str(want):
            return seen
        time.sleep(2)
    raise AssertionError(f"queue never reported {want} visible messages; last read {seen!r}")


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """On a FIFO queue without content-based deduplication, a send with a MessageDeduplicationId but
    no MessageGroupId is refused (MissingParameter, exact message) and does not consume that id: a
    valid send reusing it is enqueued, a repeat of that valid send is deduplicated, groups keep order.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-d5-") + ".fifo",
        Attributes={
            "FifoQueue": "true",
            "ContentBasedDeduplication": "false",
            "VisibilityTimeout": "120",
            "ReceiveMessageWaitTimeSeconds": "0",
        },
        tags={"sim2real-check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    for n, (group, ordinal) in enumerate(SENDS):
        sqs.send_message(
            QueueUrl=url,
            MessageBody=f"{group}|{ordinal}",
            MessageGroupId=group,
            MessageDeduplicationId=f"seed-{n}",
        )
    _await_visible(sqs, url, len(SENDS))

    rejected_body = "orphan|no-group"
    response = _error_code(
        sqs.send_message,
        QueueUrl=url,
        MessageBody=rejected_body,
        MessageDeduplicationId=REUSED_DEDUP_ID,
    )
    got = (response["Error"]["Code"], response["Error"].get("Message"))
    assert got == ("MissingParameter", MISSING_GROUP_MSG), (
        f"a FIFO SendMessage with a dedup id but no MessageGroupId was rejected with {got!r}, "
        f"expected {('MissingParameter', MISSING_GROUP_MSG)!r}"
    )
    status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert status == 400, f"the group-less send was rejected with HTTP {status!r}, expected 400"
    _await_visible(sqs, url, len(SENDS))

    # The rejected send's dedup id was never recorded, so a valid send carrying it is enqueued.
    reuse_body = "gamma|1"
    first = sqs.send_message(
        QueueUrl=url,
        MessageBody=reuse_body,
        MessageGroupId="gamma",
        MessageDeduplicationId=REUSED_DEDUP_ID,
    )
    assert first["SequenceNumber"], f"the valid send returned no SequenceNumber: {first!r}"
    _await_visible(sqs, url, len(SENDS) + 1)
    # Positive control: the id is live now, so an identical send inside the window is deduplicated.
    repeat = sqs.send_message(
        QueueUrl=url,
        MessageBody=reuse_body,
        MessageGroupId="gamma",
        MessageDeduplicationId=REUSED_DEDUP_ID,
    )
    assert repeat["MessageId"] == first["MessageId"], (
        f"a duplicate send returned MessageId {repeat['MessageId']!r}, expected the original "
        f"{first['MessageId']!r}"
    )
    _await_visible(sqs, url, len(SENDS) + 1)

    total = len(SENDS) + 1
    drained: list[tuple[str, str]] = []
    deadline = time.monotonic() + 40.0
    while time.monotonic() < deadline and len(drained) < total:
        resp = sqs.receive_message(
            QueueUrl=url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=5,
            MessageSystemAttributeNames=["MessageGroupId"],
        )
        msgs = resp.get("Messages", [])
        if not msgs:
            continue
        for m in msgs:
            drained.append((m["Body"], m["Attributes"]["MessageGroupId"]))
        sqs.delete_message_batch(
            QueueUrl=url,
            Entries=[
                {"Id": f"d{i}", "ReceiptHandle": m["ReceiptHandle"]} for i, m in enumerate(msgs)
            ],
        )

    bodies = [b for b, _g in drained]
    assert rejected_body not in bodies, "the rejected group-less message was delivered anyway"
    assert len(bodies) == total and bodies.count(reuse_body) == 1, (
        f"drained {sorted(bodies)!r}, expected {total} messages with {reuse_body!r} exactly once"
    )
    per_group: dict[str, list[int]] = collections.defaultdict(list)
    for body, group in drained:
        body_group, ordinal = body.split("|")
        assert body_group == group, (
            f"message {body!r} carried MessageGroupId {group!r}, not its own group"
        )
        per_group[group].append(int(ordinal))
    expected = {"alpha": [0, 1], "beta": [0, 1, 2, 3], "gamma": [0, 1]}
    assert dict(per_group) == expected, (
        f"per-group order is {dict(per_group)!r}, expected {expected!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
