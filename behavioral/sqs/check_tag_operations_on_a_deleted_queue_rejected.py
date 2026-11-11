"""tag-operations-on-a-deleted-queue-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-operations-on-a-deleted-queue-rejected"
GROUP = "lifecycle"
SERVICES = ["sqs"]

_TAGS = {"sim2real": "tag-operations-on-a-deleted-queue-rejected", "team": "blue"}
_NO_SUCH_QUEUE = "AWS.SimpleQueueService.NonExistentQueue"
_NO_SUCH_QUEUE_MSG = "The specified queue does not exist."
_SETTLE_S = 60.0


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Once a tagged queue is deleted, ListQueueTags, TagQueue and UntagQueue on its URL are
    refused with NonExistentQueue and its tags are unreadable; a sibling queue with the same
    tags still accepts TagQueue and UntagQueue and lists the result."""
    sqs = ctx.client("sqs")
    base = ctx.unique_name("sim2real-behav-deltags-")
    doomed = sqs.create_queue(QueueName=base + "-gone", tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_quietly(sqs, doomed))
    sibling = sqs.create_queue(QueueName=base + "-kept", tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_quietly(sqs, sibling))

    assert sqs.list_queue_tags(QueueUrl=doomed).get("Tags", {}) == _TAGS, (
        "the queue to be deleted did not carry its tags beforehand"
    )
    sqs.delete_queue(QueueUrl=doomed)

    # Deletion is eventually consistent; poll until the URL is refused, then hold every call to
    # the exact refusal.
    err: dict = {}
    deadline = time.monotonic() + _SETTLE_S
    while time.monotonic() < deadline:
        try:
            sqs.list_queue_tags(QueueUrl=doomed)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            break
        time.sleep(3)
    assert (err.get("Code"), err.get("Message")) == (_NO_SUCH_QUEUE, _NO_SUCH_QUEUE_MSG), (
        f"ListQueueTags on the deleted queue answered {err!r} within {_SETTLE_S}s"
    )
    for label, fn in (
        ("TagQueue", lambda: sqs.tag_queue(QueueUrl=doomed, Tags={"late": "x"})),
        ("UntagQueue", lambda: sqs.untag_queue(QueueUrl=doomed, TagKeys=["team"])),
        ("ListQueueTags", lambda: sqs.list_queue_tags(QueueUrl=doomed)),
    ):
        e = _error(fn)
        assert (e.get("Code"), e.get("Message")) == (_NO_SUCH_QUEUE, _NO_SUCH_QUEUE_MSG), (
            f"{label} on the deleted queue answered {e!r}"
        )

    # Positive control: the sibling is a full tag target.
    sqs.tag_queue(QueueUrl=sibling, Tags={"late": "x"})
    sqs.untag_queue(QueueUrl=sibling, TagKeys=["team"])
    got = sqs.list_queue_tags(QueueUrl=sibling).get("Tags", {})
    want = {k: v for k, v in _TAGS.items() if k != "team"} | {"late": "x"}
    assert got == want, f"the sibling queue's tags read {got!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
