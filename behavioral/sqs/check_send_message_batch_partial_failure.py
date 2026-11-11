"""send-message-batch-partial-failure."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "send-message-batch-partial-failure"
GROUP = "batch"
SERVICES = ["sqs"]

_TAGS = {"sim2real:managed": "true", "sim2real": "send-message-batch-partial-failure"}


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendMessageBatch is not atomic: an entry with disallowed characters fails while a valid sibling succeeds."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    resp = sqs.send_message_batch(
        QueueUrl=url,
        Entries=[
            {"Id": "good", "MessageBody": "this-is-fine"},
            {"Id": "bad", "MessageBody": "disallowed-char-\x01-here"},
        ],
    )

    successful = {e["Id"]: e for e in resp.get("Successful", [])}
    failed = {e["Id"]: e for e in resp.get("Failed", [])}

    assert set(successful) == {"good"}, f"Successful Ids: {sorted(successful)}"
    assert set(failed) == {"bad"}, f"Failed Ids: {sorted(failed)}"
    assert failed["bad"]["Code"] == "InvalidMessageContents", f"Failed Code: {failed['bad']['Code']!r}"
    assert failed["bad"]["SenderFault"] is True, (
        f"Failed SenderFault must be True for a client error, got {failed['bad']['SenderFault']!r}"
    )
    assert failed["bad"].get("Message") == (
        "Invalid binary character '#x1' was found in the message body, the set of allowed "
        "characters is #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]."
    ), f"Failed Message: {failed['bad'].get('Message')!r}"

    # The valid entry must actually be enqueued (the failure did not poison the whole batch).
    good_message_id = successful["good"]["MessageId"]
    received = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=10).get("Messages", [])
    assert any(m["MessageId"] == good_message_id and m["Body"] == "this-is-fine" for m in received), (
        f"expected message {good_message_id!r} with body 'this-is-fine' among received: {received}"
    )
    for m in received:
        if m["MessageId"] == good_message_id:
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
