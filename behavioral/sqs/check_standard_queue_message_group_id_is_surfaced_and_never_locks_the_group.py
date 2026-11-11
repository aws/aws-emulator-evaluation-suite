"""standard-queue-message-group-id-is-surfaced-and-never-locks-the-group."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "standard-queue-message-group-id-is-surfaced-and-never-locks-the-group"
GROUP = "fair-queues"
SERVICES = ["sqs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A standard queue accepts MessageGroupId on SendMessage and SendMessageBatch, surfaces it on
    receive only for messages that carried one, assigns no SequenceNumber, and never holds a
    group's later messages behind an in-flight one."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-fair-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    sqs.send_message(QueueUrl=url, MessageBody="a1", MessageGroupId="tenant-a")
    sqs.send_message(QueueUrl=url, MessageBody="a2", MessageGroupId="tenant-a")
    batch = sqs.send_message_batch(
        QueueUrl=url,
        Entries=[
            {"Id": "b1", "MessageBody": "b1", "MessageGroupId": "tenant-b"},
            {"Id": "n1", "MessageBody": "n1"},
        ],
    )
    assert sorted(e["Id"] for e in batch.get("Successful", [])) == ["b1", "n1"], (
        f"SendMessageBatch with a MessageGroupId entry on a standard queue must succeed for both "
        f"entries; Successful={batch.get('Successful')!r} Failed={batch.get('Failed')!r}"
    )

    # Receive one message per call and never delete or release: every message stays in flight
    # for the whole window, so a group lock would make the second tenant-a message unreachable.
    seen: dict[str, dict] = {}
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline and len(seen) < 4:
        for m in sqs.receive_message(
            QueueUrl=url,
            MaxNumberOfMessages=1,
            WaitTimeSeconds=2,
            VisibilityTimeout=300,
            MessageSystemAttributeNames=["MessageGroupId", "SequenceNumber"],
        ).get("Messages", []):
            seen[m["Body"]] = m.get("Attributes", {})

    assert sorted(seen) == ["a1", "a2", "b1", "n1"], (
        f"all four messages must be deliverable while each stays in flight (no group lock on a "
        f"standard queue); received {sorted(seen)!r}"
    )
    groups = {body: attrs.get("MessageGroupId") for body, attrs in seen.items()}
    assert groups == {"a1": "tenant-a", "a2": "tenant-a", "b1": "tenant-b", "n1": None}, (
        f"MessageGroupId surfaced on receive per body was {groups!r}; expected each message's own "
        f"group, and none on the message sent without one"
    )
    seqs = {body: attrs.get("SequenceNumber") for body, attrs in seen.items()}
    assert set(seqs.values()) == {None}, (
        f"a standard queue assigns no SequenceNumber, even to grouped messages; got {seqs!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
