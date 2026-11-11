"""fifo-batch-with-a-group-less-entry-rejected-whole-and-group-stream-unchanged."""

from __future__ import annotations

import collections
import time

from behavioral_harness import tags

CHECK = "fifo-batch-with-a-group-less-entry-rejected-whole-and-group-stream-unchanged"
GROUP = "fifo"
SERVICES = ["sqs"]

GROUPS = ["red", "green", "blue"]
PER_GROUP = 3
TOTAL = len(GROUPS) * PER_GROUP
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
    """A FIFO SendMessageBatch with one entry lacking MessageGroupId is refused whole with
    InvalidParameterValue and the exact message, enqueuing none of its valid siblings; the same
    batch with the group restored lands in full and every group drains in send order.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-d5-") + ".fifo",
        Attributes={
            "FifoQueue": "true",
            "ContentBasedDeduplication": "true",
            "VisibilityTimeout": "120",
            "ReceiveMessageWaitTimeSeconds": "0",
        },
        tags={"sim2real-check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    # Seed groups through a batch, entries interleaved across groups.
    seed = [
        {"Id": f"s{i}", "MessageBody": f"{GROUPS[i % 3]}|{i // 3}", "MessageGroupId": GROUPS[i % 3]}
        for i in range(TOTAL)
    ]
    for chunk in (seed[:5], seed[5:]):
        ok = sqs.send_message_batch(QueueUrl=url, Entries=chunk)
        assert not ok.get("Failed"), f"a valid seed batch had failed entries: {ok.get('Failed')!r}"
    _await_visible(sqs, url, TOTAL)

    # The refused batch's bodies differ from the corrected batch's, so content-based deduplication
    # can never hide a refused sibling that was enqueued anyway.
    bad = [
        {"Id": "b0", "MessageBody": "red|refused", "MessageGroupId": "red"},
        {"Id": "b1", "MessageBody": "green|refused"},
        {"Id": "b2", "MessageBody": "blue|refused", "MessageGroupId": "blue"},
    ]
    response = _error_code(sqs.send_message_batch, QueueUrl=url, Entries=bad)
    got = (response["Error"]["Code"], response["Error"].get("Message"))
    assert got == ("InvalidParameterValue", MISSING_GROUP_MSG), (
        f"a FIFO batch with a group-less entry was refused with {got!r}, "
        f"expected {('InvalidParameterValue', MISSING_GROUP_MSG)!r}"
    )
    status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert status == 400, f"the batch was refused with HTTP {status!r}, expected 400"
    _await_visible(sqs, url, TOTAL)

    fixed = [
        {"Id": e["Id"], "MessageBody": f"{g}|{PER_GROUP}", "MessageGroupId": g}
        for e, g in zip(bad, GROUPS, strict=True)
    ]
    ok = sqs.send_message_batch(QueueUrl=url, Entries=fixed)
    assert not ok.get("Failed") and sorted(e["Id"] for e in ok["Successful"]) == [
        "b0",
        "b1",
        "b2",
    ], f"the corrected batch did not land in full: {ok!r}"
    _await_visible(sqs, url, TOTAL + 3)

    drained: list[tuple[str, str]] = []
    deadline = time.monotonic() + 40.0
    while time.monotonic() < deadline and len(drained) < TOTAL + 3:
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

    bodies = sorted(b for b, _g in drained)
    leaked = [b for b in bodies if b.endswith("|refused")]
    assert not leaked, f"siblings of the refused batch were enqueued anyway: {leaked!r}"
    assert len(bodies) == TOTAL + 3 and len(set(bodies)) == TOTAL + 3, (
        f"drained {bodies!r}, expected {TOTAL + 3} distinct messages (nothing from the refused batch)"
    )
    per_group: dict[str, list[int]] = collections.defaultdict(list)
    for body, group in drained:
        body_group, ordinal = body.split("|")
        assert body_group == group, (
            f"message {body!r} carried MessageGroupId {group!r}, not its own group"
        )
        per_group[group].append(int(ordinal))
    expected = {g: list(range(PER_GROUP + 1)) for g in GROUPS}
    assert dict(per_group) == expected, (
        f"per-group order is {dict(per_group)!r}, expected {expected!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
