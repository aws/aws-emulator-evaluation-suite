"""send-message-batch-duplicate-ids-rejected-atomically."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-message-batch-duplicate-ids-rejected-atomically"
GROUP = "overly-permissive"
SERVICES = ["sqs"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendMessageBatch entries sharing the same Id are rejected wholesale (BatchEntryIdsNotDistinct);
    none of the entries land, unlike a per-entry Failed/Successful split. Distinct Ids succeed fully."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    code, message = _error(
        lambda: sqs.send_message_batch(
            QueueUrl=url,
            Entries=[
                {"Id": "dup", "MessageBody": "first-copy"},
                {"Id": "dup", "MessageBody": "second-copy"},
            ],
        )
    )
    assert code == "AWS.SimpleQueueService.BatchEntryIdsNotDistinct", (
        f"expected AWS.SimpleQueueService.BatchEntryIdsNotDistinct, got {code!r}"
    )
    assert message == "Id dup repeated.", f"expected message 'Id dup repeated.', got {message!r}"

    # Effect absent: this is a whole-request rejection, not a per-entry partial failure --
    # neither message body must have landed on the queue.
    leftover = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get("Messages", [])
    assert leftover == [], f"expected no messages to have landed, found {leftover!r}"

    # Positive control: the same two bodies with distinct Ids succeed in full.
    resp = sqs.send_message_batch(
        QueueUrl=url,
        Entries=[
            {"Id": "a", "MessageBody": "first-copy"},
            {"Id": "b", "MessageBody": "second-copy"},
        ],
    )
    assert len(resp.get("Successful", [])) == 2, f"expected 2 Successful entries, got {resp!r}"
    assert not resp.get("Failed"), f"expected no Failed entries, got {resp.get('Failed')!r}"

    # Terminal assertion is an independent read at the destination, not the mutating call's
    # own response: both distinct-Id bodies must actually be visible on the queue.
    landed = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get("Messages", [])
    landed_bodies = sorted(m["Body"] for m in landed)
    assert landed_bodies == ["first-copy", "second-copy"], (
        f"expected both distinct-Id bodies to have landed, got {landed_bodies!r}"
    )


def _error(fn):
    """Return (Error.Code, Error.Message) of the ClientError fn raises; raise if fn succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected the call to be refused with an error, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
