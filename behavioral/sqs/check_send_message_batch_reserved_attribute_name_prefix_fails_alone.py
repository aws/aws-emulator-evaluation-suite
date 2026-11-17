"""send-message-batch-reserved-attribute-name-prefix-fails-alone."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "send-message-batch-reserved-attribute-name-prefix-fails-alone"
GROUP = "message-attributes"
SERVICES = ["sqs"]

_RESERVED_MESSAGE = (
    "You can't use message attribute names beginning with 'AWS.' or 'Amazon'. These strings are "
    "reserved for internal use."
)


def _poll_until_both(sqs, url, want_bodies: set[str], *, timeout_s: float) -> dict:
    """Receive (and delete) until every body in ``want_bodies`` has been seen; body -> message."""
    seen: dict = {}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and not want_bodies <= set(seen):
        for msg in sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2, MessageAttributeNames=["All"]
        ).get("Messages", []):
            seen[msg["Body"]] = msg
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    missing = sorted(want_bodies - set(seen))
    assert not missing, f"within {timeout_s}s the queue never delivered {missing!r}; saw {sorted(seen)!r}"
    return seen


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """In SendMessageBatch, an entry whose message attribute name begins with the reserved 'AWS.'
    prefix fails alone (SenderFault, exact message) while a sibling entry with a legal
    ``color.*``-namespaced attribute name is enqueued with its value intact."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-sqs-"), tags={"sim2real": CHECK})[
        "QueueUrl"
    ]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    resp = sqs.send_message_batch(
        QueueUrl=url,
        Entries=[
            {
                "Id": "legal",
                "MessageBody": "batch-reserved-prefix-legal",
                "MessageAttributes": {"color.primary": {"DataType": "String", "StringValue": "red"}},
            },
            {
                "Id": "reserved",
                "MessageBody": "batch-reserved-prefix-refused",
                "MessageAttributes": {"AWS.Internal": {"DataType": "String", "StringValue": "x"}},
            },
        ],
    )

    successful_ids = [e["Id"] for e in resp.get("Successful", [])]
    assert successful_ids == ["legal"], (
        f"only the 'legal' entry may succeed, got Successful={resp.get('Successful')!r}"
    )

    failed_entries = resp.get("Failed", [])
    assert [e["Id"] for e in failed_entries] == ["reserved"], (
        f"the 'reserved' entry must fail alone, got Failed={failed_entries!r}"
    )
    [failed_entry] = failed_entries
    code = failed_entry["Code"]
    message = failed_entry["Message"]
    assert (code, message) == ("InvalidParameterValue", _RESERVED_MESSAGE), (
        f"the 'reserved' entry failed with ({code!r}, {message!r}), expected "
        f"('InvalidParameterValue', {_RESERVED_MESSAGE!r})"
    )
    assert failed_entry["SenderFault"] is True, (
        f"the reserved-prefix failure must be SenderFault, got {failed_entry['SenderFault']!r}"
    )

    seen = _poll_until_both(sqs, url, {"batch-reserved-prefix-legal"}, timeout_s=30.0)
    got_attrs = seen["batch-reserved-prefix-legal"].get("MessageAttributes") or {}
    assert set(got_attrs) == {"color.primary"}, (
        f"the enqueued message carried attributes {sorted(got_attrs)}, expected only 'color.primary'"
    )
    assert got_attrs["color.primary"]["StringValue"] == "red", (
        f"'color.primary' carried {got_attrs['color.primary'].get('StringValue')!r}, expected 'red'"
    )

    # The refused entry must never have been enqueued: drain any remaining traffic and confirm.
    leftover = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get(
        "Messages", []
    )
    assert not any(m["Body"] == "batch-reserved-prefix-refused" for m in leftover), (
        "the refused entry was enqueued despite being reported as Failed"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
