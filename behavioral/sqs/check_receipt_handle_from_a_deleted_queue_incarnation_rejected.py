"""receipt-handle-from-a-deleted-queue-incarnation-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "receipt-handle-from-a-deleted-queue-incarnation-rejected"
GROUP = "lifecycle"
SERVICES = ["sqs"]

_OLD_TAGS = {"sim2real": "receipt-handle-from-a-deleted-queue-incarnation-rejected",
             "generation": "old"}
_NEW_TAGS = {"sim2real": "receipt-handle-from-a-deleted-queue-incarnation-rejected"}
_NO_SUCH_QUEUE = "AWS.SimpleQueueService.NonExistentQueue"
_NO_SUCH_QUEUE_MSG = "The specified queue does not exist."
_RECENT = "AWS.SimpleQueueService.QueueDeletedRecently"
_RECREATE_DEADLINE_S = 150.0


def _error(fn) -> dict:
    """The botocore Error dict ``fn`` raises. An unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _delete_quietly(sqs, url: str) -> None:
    try:
        sqs.delete_queue(QueueUrl=url)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != _NO_SUCH_QUEUE:
            raise


def _receive_one(sqs, url: str, visibility: int) -> dict:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(QueueUrl=url, WaitTimeSeconds=3,
                                   VisibilityTimeout=visibility).get("Messages", [])
        if msgs:
            return msgs[0]
    raise AssertionError("no message was received from the queue within 30s")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A receipt handle from a deleted queue is refused with NonExistentQueue by DeleteMessage and
    ChangeMessageVisibility on a same-name recreated queue, which keeps none of the old tags or
    messages, while the new queue's own message and handle behave normally."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-incarn-")
    url = sqs.create_queue(QueueName=name, tags=_OLD_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_quietly(sqs, url))
    sqs.send_message(QueueUrl=url, MessageBody="old-generation")
    old = _receive_one(sqs, url, 300)
    assert old["Body"] == "old-generation", f"received {old['Body']!r}"
    old_handle = old["ReceiptHandle"]

    sqs.delete_queue(QueueUrl=url)
    new_url = None
    last: dict = {}
    deadline = time.monotonic() + _RECREATE_DEADLINE_S
    while new_url is None and time.monotonic() < deadline:
        try:
            new_url = sqs.create_queue(QueueName=name, tags=_NEW_TAGS)["QueueUrl"]
            ctx.on_cleanup(lambda: _delete_quietly(sqs, new_url))
        except ClientError as exc:
            last = exc.response.get("Error", {})
            assert last.get("Code") == _RECENT, f"recreating the name answered {last!r}"
            time.sleep(5)
    assert new_url is not None, (
        f"the name was still refused {_RECREATE_DEADLINE_S}s after the delete: {last!r}"
    )
    assert new_url == url, "the recreated queue has a different URL than the deleted one"

    for label, fn in (
        ("DeleteMessage", lambda: sqs.delete_message(QueueUrl=new_url, ReceiptHandle=old_handle)),
        ("ChangeMessageVisibility", lambda: sqs.change_message_visibility(
            QueueUrl=new_url, ReceiptHandle=old_handle, VisibilityTimeout=0)),
    ):
        err = _error(fn)
        assert (err.get("Code"), err.get("Message")) == (_NO_SUCH_QUEUE, _NO_SUCH_QUEUE_MSG), (
            f"{label} on the recreated queue with the old incarnation's handle answered {err!r}"
        )

    got_tags = sqs.list_queue_tags(QueueUrl=new_url).get("Tags", {})
    assert got_tags == _NEW_TAGS, f"the recreated queue carries tags {got_tags!r}"

    sqs.send_message(QueueUrl=new_url, MessageBody="new-generation")
    err = _error(lambda: sqs.delete_message(QueueUrl=new_url, ReceiptHandle=old_handle))
    assert (err.get("Code"), err.get("Message")) == (_NO_SUCH_QUEUE, _NO_SUCH_QUEUE_MSG), (
        f"with a message on the recreated queue, the old handle's DeleteMessage answered {err!r}"
    )

    # Positive control: the new queue's own message and handle behave normally, and the old
    # message is not there.
    fresh = _receive_one(sqs, new_url, 60)
    assert fresh["Body"] == "new-generation", (
        f"the recreated queue delivered {fresh['Body']!r}; the old message must not survive"
    )
    sqs.change_message_visibility(QueueUrl=new_url, ReceiptHandle=fresh["ReceiptHandle"],
                                  VisibilityTimeout=0)
    again = _receive_one(sqs, new_url, 60)
    assert again["Body"] == "new-generation", f"after release the queue delivered {again['Body']!r}"
    sqs.delete_message(QueueUrl=new_url, ReceiptHandle=again["ReceiptHandle"])
    rest = sqs.receive_message(QueueUrl=new_url, MaxNumberOfMessages=10, WaitTimeSeconds=3)
    assert rest.get("Messages", []) == [], (
        f"after deleting its one message the recreated queue still delivered "
        f"{[m['Body'] for m in rest['Messages']]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
