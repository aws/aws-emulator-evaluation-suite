"""purge-empties."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "purge-empties"
GROUP = 'state'
SERVICES = ['sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": "purge-empties"}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """PurgeQueue removes all messages; the sent messages are first confirmed receivable so a
    SendMessage that silently drops messages cannot pass."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    sent_ids = set()
    for i in range(3):
        resp = sqs.send_message(QueueUrl=url, MessageBody=f"purge-{i}")
        sent_ids.add(resp["MessageId"])

    seen_ids = set()
    for _ in range(30):
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
        for msg in resp.get("Messages", []):
            seen_ids.add(msg["MessageId"])
            sqs.change_message_visibility(
                QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"], VisibilityTimeout=0
            )
        if sent_ids <= seen_ids:
            break
    else:
        raise AssertionError(
            f"expected all {len(sent_ids)} sent messages to be receivable before purge, "
            f"only observed {len(sent_ids & seen_ids)}"
        )

    sqs.purge_queue(QueueUrl=url)
    for _ in range(30):
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
        messages = resp.get("Messages", [])
        if not messages:
            return
        for msg in messages:
            sqs.change_message_visibility(
                QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"], VisibilityTimeout=0
            )
    raise AssertionError("queue still returned messages after PurgeQueue")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
