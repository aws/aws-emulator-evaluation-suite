"""queue-deleted-recently-on-fast-recreate-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "queue-deleted-recently-on-fast-recreate-rejected"
GROUP = 'lifecycle'
SERVICES = ['sqs']

_TAGS = {"sim2real": "queue-deleted-recently-on-fast-recreate-rejected"}
CODE_RECENT = "AWS.SimpleQueueService.QueueDeletedRecently"
MSG_RECENT = ("You must wait 60 seconds after deleting a queue before you can create another "
              "with the same name.")
CODE_MISSING = "AWS.SimpleQueueService.NonExistentQueue"
MSG_MISSING = "The specified queue does not exist."


def _err(fn):
    """(Code, Message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        e = exc.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateQueue with the name of a queue deleted moments earlier is refused with
    QueueDeletedRecently and creates nothing; a different fresh name is unaffected.
    """
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-qdr-")
    url = sqs.create_queue(
        QueueName=name, Attributes={"VisibilityTimeout": "45"}, tags=_TAGS)["QueueUrl"]
    deleted = []

    def _delete_original():
        if not deleted:
            sqs.delete_queue(QueueUrl=url)

    ctx.on_cleanup(_delete_original)
    sqs.delete_queue(QueueUrl=url)
    deleted.append(True)

    code, msg = _err(lambda: sqs.create_queue(QueueName=name, tags=_TAGS))
    assert code == CODE_RECENT, f"recreating a just-deleted name gave code {code!r}"
    assert msg == MSG_RECENT, f"recreating a just-deleted name gave message {msg!r}"

    code, msg = _err(lambda: sqs.get_queue_url(QueueName=name))
    assert (code, msg) == (CODE_MISSING, MSG_MISSING), (
        f"the refused recreate left something resolvable: GetQueueUrl gave {(code, msg)!r}"
    )

    # Positive control: the refusal is about the deleted name, not CreateQueue in general.
    other = ctx.unique_name("sim2real-behav-qdr-other-")
    other_url = sqs.create_queue(QueueName=other, tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=other_url))
    assert sqs.get_queue_url(QueueName=other)["QueueUrl"] == other_url, (
        "positive control: a fresh name was not resolvable after CreateQueue"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
